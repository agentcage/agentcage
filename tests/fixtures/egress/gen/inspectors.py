"""Record tests/fixtures/egress/inspectors.json from the Python egress.

    uv run python tests/fixtures/egress/gen/inspectors.py

Each case is a script: steps run in order against one inspector
instance, each with the value the Python returned recorded under
``expect``. ``tests/test_egress_corpus_inspectors.py`` replays every
case against the Python (``run_case`` below) and the Rust port asserts
the same file.

Domain steps (``inspector: "domain"``), with the clock pinned to the
case's ``now`` (``set_now`` moves it):

* ``configure`` {config}            -> null
* ``inspect`` {host}                -> verdict or null
* ``matches`` / ``matched_expired`` / ``is_granted`` / ``is_grant_only``
  / ``matches_baseline`` {host}     -> bool / str|null
* ``baseline_active_covers`` {domain} -> bool (the removal endpoint's
  and the watcher's expiry-aware baseline check)
* ``grant`` {domain, expires_at, reason, source} -> null
* ``revoke`` {domain}               -> bool
* ``drop_expired`` {now_iso}        -> [domain, ...]
* ``granted_entries`` / ``baseline_list`` / ``mode``
* ``reconcile`` {overlay}           -> null: the overlay text is loaded
  and reconciled the way the Policy API does on an overlay mtime change
* ``parse_overlay`` {overlay}       -> [entry, ...]
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import types
from datetime import datetime as _real_datetime
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))
import _common  # noqa: E402
from _common import ctx, noise, to_context, verdict  # noqa: E402

_OUT = _common.FIXTURES / "inspectors.json"

import addon as _addon  # noqa: E402
import inspectors.domain as _domain_mod  # noqa: E402
import policy_api as _policy_api  # noqa: E402
import watcher as _watcher  # noqa: E402
from inspectors.body_size import BodySizeInspector  # noqa: E402
from inspectors.content_type import ContentTypeInspector  # noqa: E402
from inspectors.domain import DomainInspector  # noqa: E402
from inspectors.entropy import EntropyInspector  # noqa: E402

COMMENT = (
    "Built-in inspector verdicts and the domain inspector's grant API, "
    "recorded from the Python egress by gen/inspectors.py. Do not edit by "
    "hand; see tests/fixtures/egress/README.md."
)


# ── Clock pinning ────────────────────────────────────────────

_ORIG_DOMAIN_DATETIME = _domain_mod.datetime
_ORIG_WATCHER_NOW = _watcher._now


def _pin_now(now_iso: str) -> None:
    now_dt = _real_datetime.fromisoformat(now_iso)

    class _Clock:
        now = staticmethod(lambda tz=None: now_dt)
        fromisoformat = staticmethod(_real_datetime.fromisoformat)

    _domain_mod.datetime = _Clock
    _watcher._now = lambda: now_dt


def _unpin() -> None:
    _domain_mod.datetime = _ORIG_DOMAIN_DATETIME
    _watcher._now = _ORIG_WATCHER_NOW


# ── Domain steps ─────────────────────────────────────────────


def _load_overlay(text: str) -> list:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "grants.yaml")
        with open(path, "w") as f:
            f.write(text)
        return _policy_api.PolicyApi._load_overlay(
            types.SimpleNamespace(_grants_path=path))


def _reconcile(dom: DomainInspector, text: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "grants.yaml")
        with open(path, "w") as f:
            f.write(text)
        ns = types.SimpleNamespace(
            _grants_path=path, dom=dom, _grants_mtime=0.0,
            _publish_dns_domains=lambda: None,
        )
        ns._load_overlay = lambda: _policy_api.PolicyApi._load_overlay(ns)
        _policy_api.PolicyApi._reconcile_from_overlay(ns)


def _domain_step(dom: DomainInspector, step: dict):
    op = step["op"]
    if op == "set_now":
        _pin_now(step["now"])
        return None
    if op == "configure":
        dom.configure(step["config"])
        return None
    if op == "inspect":
        from inspectors.base import InspectionContext
        ictx = InspectionContext(
            url=f"https://{step['host']}/", host=step["host"], method="GET",
            headers=[], content_type="", body_bytes=None, body_text=None,
            body_size=0,
        )
        return verdict(dom.inspect_request(ictx))
    if op == "matches":
        return dom._matches(step["host"])
    if op == "matched_expired":
        return dom._matched_expired(step["host"])
    if op == "is_granted":
        return dom.is_granted(step["host"])
    if op == "is_grant_only":
        return dom.is_grant_only(step["host"])
    if op == "matches_baseline":
        return dom.matches_baseline(step["host"])
    if op == "baseline_active_covers":
        return _watcher.Watcher._baseline_covers(
            types.SimpleNamespace(dom=dom), step["domain"])
    if op == "grant":
        dom.grant(step["domain"], expires_at=step.get("expires_at", ""),
                  reason=step.get("reason", ""),
                  source=step.get("source", "policy-hook"))
        return None
    if op == "revoke":
        return dom.revoke(step["domain"])
    if op == "drop_expired":
        return dom.drop_expired(step["now_iso"])
    if op == "granted_entries":
        return dom.granted_entries()
    if op == "baseline_list":
        return dom.baseline_list()
    if op == "mode":
        return dom.mode
    if op == "reconcile":
        _reconcile(dom, step["overlay"])
        return None
    if op == "parse_overlay":
        return _load_overlay(step["overlay"])
    raise ValueError(f"unknown domain op {op!r}")


# ── Built-in inspector steps ─────────────────────────────────

_BUILTIN_CLASSES = {
    "body-size": BodySizeInspector,
    "entropy": EntropyInspector,
    "content-type": ContentTypeInspector,
}


def _builtin_step(insp, step: dict):
    op = step["op"]
    if op == "configure":
        try:
            insp.configure(step["config"])
        except Exception:  # noqa: BLE001 - any raise is a refused config
            return "error"
        return None
    if op == "inspect":
        return verdict(insp.inspect_request(to_context(step["ctx"])))
    raise ValueError(f"unknown op {op!r}")


# ── Chain construction ───────────────────────────────────────


class _StubPlugin:
    def __init__(self, name):
        self.name = name

    def configure(self, config):
        pass

    def inspect_request(self, ctx):
        return None

    def inspect_response(self, ctx):
        return None


def _chain_build(step: dict):
    """Plan, configure and relay-wrap the chain ``config`` describes.

    ``plugins`` maps a ``path:`` to the name the plugin declares, or to
    null for one that fails to load.
    """
    plugins = step.get("plugins", {})
    warnings: list = []

    def load(path, allowed_dirs=None):
        declared = plugins.get(path)
        if declared is None:
            raise ImportError(f"cannot load {path}")
        return _StubPlugin(declared)

    saved = (_addon.load_inspector_from_file, _addon.ctx)
    _addon.load_inspector_from_file = load
    _addon.ctx = types.SimpleNamespace(log=types.SimpleNamespace(
        warn=warnings.append, info=lambda *_: None))
    try:
        a = _addon.Agentcage()
        a.cfg = step["config"]
        try:
            plan = a._plan_inspectors(())
            for slot in plan:
                slot[0].configure(slot[1])
        except Exception:  # noqa: BLE001 - any raise is a refused config
            return "error"
        a.inspectors = tuple(slot[0] for slot in plan)
        return {
            "slots": [
                [slot[0].name, "plugin" if slot[2] else "builtin", slot[2],
                 slot[1]]
                for slot in plan
            ],
            "relay": [i.name for i in a._build_relay_inspectors()],
            "warnings": warnings,
        }
    finally:
        _addon.load_inspector_from_file, _addon.ctx = saved


# ── Python whitespace (``\s`` / ``str.isspace``) ──────────────


def _whitespace(op: str) -> list:
    import re
    chars = (chr(c) for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF)
    if op == "isspace":
        return [ord(c) for c in chars if c.isspace()]
    pat = re.compile(r"\s")
    return [ord(c) for c in chars if pat.match(c)]


def run_case(case: dict) -> list:
    """Run one case; return the per-step results, in order."""
    kind = case["inspector"]
    if kind == "domain":
        _pin_now(case["now"])
        try:
            dom = DomainInspector()
            return [_domain_step(dom, step) for step in case["steps"]]
        finally:
            _unpin()
    if kind in _BUILTIN_CLASSES:
        insp = _BUILTIN_CLASSES[kind]()
        return [_builtin_step(insp, step) for step in case["steps"]]
    if kind == "chain":
        return [_chain_build(step) for step in case["steps"]]
    if kind == "whitespace":
        return [_whitespace(step["op"]) for step in case["steps"]]
    raise ValueError(f"unknown inspector {kind!r}")


# ── Cases ────────────────────────────────────────────────────

NOW = "2026-08-30T14:20:00+00:00"
PAST = "2000-01-01T00:00:00+00:00"
FUTURE = "2999-01-01T00:00:00+00:00"


def _d(name, steps, now=NOW):
    return {"name": name, "inspector": "domain", "now": now, "steps": steps}


def _cfg(config):
    return {"op": "configure", "config": config}


def _hosts(op, *hosts):
    return [{"op": op, "host": h} for h in hosts]


def _inspect(*hosts):
    return _hosts("inspect", *hosts)


def domain_cases() -> list:
    c = []
    # Modes and matching.
    c.append(_d("legacy allowlist mode", [
        _cfg({"mode": "allowlist", "list": ["api.anthropic.com"]}),
        {"op": "mode"},
        *_inspect("api.anthropic.com", "evil.com", "sub.api.anthropic.com",
                  "anthropic.com"),
    ]))
    c.append(_d("legacy allowlist suffix", [
        _cfg({"mode": "allowlist", "list": ["anthropic.com"]}),
        *_inspect("api.anthropic.com", "notanthropic.com", "anthropic.com.evil"),
    ]))
    c.append(_d("legacy blocklist", [
        _cfg({"mode": "blocklist", "list": ["evil.com"]}),
        {"op": "mode"},
        *_inspect("evil.com", "x.evil.com", "api.anthropic.com", "notevil.com"),
    ]))
    for name, cfg in [
        ("no mode default-deny", {}),
        ("empty mode default-deny", {"mode": ""}),
        ("unknown mode default-deny", {"mode": "bogus"}),
        ("null mode default-deny", {"mode": None, "list": ["a.com"]}),
    ]:
        c.append(_d(name, [_cfg(cfg), {"op": "mode"},
                           *_inspect("anything.example.com", "a.com", "")]))
    c.append(_d("empty allowlist blocks everything", [
        _cfg({"allow": []}), {"op": "mode"}, *_inspect("anything.example.com"),
    ]))
    c.append(_d("allow wins over block and mode", [
        _cfg({"allow": ["a.com"], "block": ["b.com"], "mode": "blocklist"}),
        {"op": "mode"}, {"op": "baseline_list"}, *_inspect("a.com", "b.com"),
    ]))
    c.append(_d("block wins over legacy mode", [
        _cfg({"block": ["b.com"], "mode": "allowlist", "list": ["a.com"]}),
        {"op": "mode"}, {"op": "baseline_list"}, *_inspect("a.com", "b.com"),
    ]))
    c.append(_d("case and dots", [
        _cfg({"allow": ["Example.COM", "trailing.org.", "a..b.net"]}),
        {"op": "baseline_list"},
        *_inspect("EXAMPLE.com", "Sub.Example.Com", "example.com.",
                  "trailing.org", "trailing.org.", "x.trailing.org.",
                  "a..b.net", "b.net", ".example.com", "", "."),
        *_hosts("matches", "example.com.", "x.trailing.org."),
        *_hosts("matches_baseline", "example.com.", "EXAMPLE.COM..",
                "trailing.org", "x.trailing.org"),
    ]))
    c.append(_d("blocklist suffix and case", [
        _cfg({"block": ["Evil.com"]}),
        *_inspect("EVIL.COM", "a.evil.com", "evil.com.", "good.com"),
    ]))
    # matches_baseline.
    c.append(_d("matches_baseline", [
        _cfg({"allow": ["api.anthropic.com", "anthropic.org"]}),
        {"op": "grant", "domain": "granted.dev"},
        *_hosts("matches_baseline", "api.anthropic.com", "x.anthropic.org",
                "evil.com", "granted.dev", "sub.granted.dev"),
        *_hosts("matches", "granted.dev", "sub.granted.dev"),
    ]))
    # Expiry semantics.
    c.append(_d("permanent specific unblocked by expired broader", [
        _cfg({"allow": ["api.example.com", "example.com"],
              "expires": {"example.com": PAST}}),
        *_hosts("matched_expired", "api.example.com", "example.com",
                "other.example.com"),
        *_inspect("api.example.com", "example.com", "other.example.com"),
    ]))
    c.append(_d("permanent broader unblocks expired specific", [
        _cfg({"allow": ["example.com", "sub.example.com"],
              "expires": {"sub.example.com": PAST}}),
        *_hosts("matched_expired", "sub.example.com", "x.sub.example.com"),
        *_inspect("sub.example.com"),
    ]))
    c.append(_d("every matching suffix expired names the longest", [
        _cfg({"allow": ["example.com", "sub.example.com"],
              "expires": {"sub.example.com": PAST, "example.com": PAST}}),
        *_hosts("matched_expired", "x.sub.example.com", "example.com"),
        *_inspect("x.sub.example.com", "y.example.com"),
    ]))
    c.append(_d("future and expired mixed", [
        _cfg({"allow": ["example.com", "sub.example.com"],
              "expires": {"sub.example.com": PAST, "example.com": FUTURE}}),
        *_inspect("x.sub.example.com"),
    ]))
    c.append(_d("expires list form and key normalisation", [
        _cfg({"allow": ["a.com", "b.com", "c.com", "d.com"],
              "expires": [
                  {"domain": "A.COM.", "expires_at": PAST},
                  {"domain": "b.com", "expires_at": ""},
                  {"domain": "", "expires_at": PAST},
                  "c.com",
                  {"domain": "d.com"},
              ]}),
        *_inspect("a.com", "b.com", "c.com", "d.com"),
    ]))
    c.append(_d("expires map falsy and non-string values", [
        _cfg({"allow": ["a.com", "b.com", "c.com", "d.com"],
              "expires": {"a.com": "", "b.com": None, "c.com": 0,
                          "d.com": 20000101}}),
        *_inspect("a.com", "b.com", "c.com", "d.com"),
    ]))
    c.append(_d("expires of the wrong type is ignored", [
        _cfg({"allow": ["a.com"], "expires": "a.com"}), *_inspect("a.com"),
    ]))
    c.append(_d("expires keys are dot-stripped, baseline is not", [
        _cfg({"allow": ["a.com."], "expires": {"a.com.": PAST}}),
        *_inspect("a.com.", "a.com"),
        {"op": "baseline_active_covers", "domain": "a.com."},
    ]))
    for label, exp in [
        ("Z suffix past", "2026-08-30T14:19:59Z"),
        ("Z suffix future", "2026-08-30T14:20:01Z"),
        ("exactly now", NOW),
        ("one microsecond later", "2026-08-30T14:20:00.000001+00:00"),
        ("positive offset past", "2026-08-30T14:20:00+05:00"),
        ("negative offset future", "2026-08-30T14:19:00-05:00"),
        ("same instant other offset", "2026-08-30T09:20:00-05:00"),
        ("basic format past", "20260830T142000+0000"),
        ("space separator past", "2026-08-30 14:00:00+00:00"),
        ("week date past", "2026-W35-1T00:00:00+00:00"),
        ("fraction comma", "2026-08-30T14:19:59,5+00:00"),
        ("seconds offset", "2026-08-30T14:20:00+00:00:30"),
        ("lowercase z fails open", "2000-01-01T00:00:00z"),
        ("naive fails open", "2000-01-01T00:00:00"),
        ("date only fails open", "2000-01-01"),
        ("garbage fails open", "not-a-date"),
        ("non-ascii fails open", "２０００-01-01T00:00:00+00:00"),
        ("offset too large fails open", "2000-01-01T00:00:00+24:00"),
    ]:
        c.append(_d(f"expiry parse: {label}", [
            _cfg({"allow": ["example.com"], "expires": {"example.com": exp}}),
            *_hosts("matched_expired", "example.com"),
            *_inspect("example.com"),
            {"op": "baseline_active_covers", "domain": "example.com"},
        ]))
    # Grants.
    c.append(_d("expired grant shadowed by permanent baseline", [
        _cfg({"allow": ["example.com"]}),
        {"op": "grant", "domain": "sub.example.com", "expires_at": PAST},
        *_hosts("matched_expired", "sub.example.com"),
        *_inspect("sub.example.com"),
    ]))
    c.append(_d("only expired grant is blocked", [
        _cfg({"allow": ["unrelated.com"]}),
        {"op": "grant", "domain": "past.com", "expires_at": PAST},
        *_hosts("matched_expired", "past.com", "x.past.com"),
        *_inspect("past.com", "x.past.com"),
    ]))
    c.append(_d("baseline expiry wins over grant expiry", [
        _cfg({"allow": ["x.com"], "expires": {"x.com": PAST}}),
        {"op": "grant", "domain": "x.com", "expires_at": FUTURE},
        *_inspect("x.com"),
        {"op": "baseline_active_covers", "domain": "x.com"},
    ]))
    c.append(_d("grant lifecycle", [
        _cfg({"allow": ["base.com"]}),
        {"op": "grant", "domain": "New.Example.COM.", "expires_at": FUTURE,
         "reason": "docs", "source": "decider"},
        {"op": "grant", "domain": "a.dev", "expires_at": "", "source": ""},
        {"op": "grant", "domain": "...", "expires_at": ""},
        {"op": "granted_entries"},
        *_hosts("is_granted", "new.example.com", "NEW.example.com.",
                "sub.new.example.com", "a.dev"),
        *_inspect("new.example.com", "sub.new.example.com", "a.dev"),
        {"op": "revoke", "domain": "NEW.EXAMPLE.COM"},
        {"op": "revoke", "domain": "new.example.com"},
        *_inspect("new.example.com"),
        {"op": "granted_entries"},
    ]))
    c.append(_d("grant is a no-op outside allowlist mode", [
        _cfg({"block": ["evil.com"]}),
        {"op": "grant", "domain": "evil.com"},
        {"op": "granted_entries"},
        *_inspect("evil.com"),
        _cfg({}),
        {"op": "grant", "domain": "a.com"},
        {"op": "granted_entries"},
    ]))
    c.append(_d("reconfigure keeps grants", [
        _cfg({"allow": ["a.com"]}),
        {"op": "grant", "domain": "g.com"},
        _cfg({"allow": ["b.com"]}),
        *_inspect("a.com", "b.com", "g.com"),
        _cfg({"block": ["g.com"]}),
        *_inspect("g.com", "h.com"),
        {"op": "granted_entries"},
        _cfg({"allow": []}),
        *_inspect("g.com"),
    ]))
    c.append(_d("is_grant_only", [
        _cfg({"allow": ["example.com", "Upper.ORG"]}),
        {"op": "grant", "domain": "granted.dev"},
        {"op": "grant", "domain": "sub.example.com"},
        {"op": "grant", "domain": "upper.org"},
        *_hosts("is_grant_only", "granted.dev", "a.granted.dev",
                "GRANTED.DEV.", "sub.example.com", "example.com",
                "upper.org", "nothing.com", ""),
    ]))
    c.append(_d("drop_expired is lexical and keeps overlay order", [
        _cfg({"allow": []}),
        {"op": "grant", "domain": "z.com", "expires_at": PAST},
        {"op": "grant", "domain": "a.com", "expires_at": PAST},
        {"op": "grant", "domain": "m.com", "expires_at": FUTURE},
        {"op": "grant", "domain": "p.com", "expires_at": ""},
        # Lexically before NOW, though an instant five hours later.
        {"op": "grant", "domain": "lex.com",
         "expires_at": "2026-08-30T14:19:00-05:00"},
        {"op": "grant", "domain": "eq.com", "expires_at": NOW},
        # Re-granting keeps the original position.
        {"op": "grant", "domain": "z.com", "expires_at": PAST,
         "reason": "again"},
        {"op": "drop_expired", "now_iso": NOW},
        {"op": "granted_entries"},
        {"op": "drop_expired", "now_iso": "3000-01-01T00:00:00+00:00"},
        {"op": "granted_entries"},
    ]))
    c.append(_d("baseline_active_covers", [
        _cfg({"allow": ["example.com", "sub.example.com", "gone.org"],
              "expires": {"sub.example.com": PAST, "gone.org": PAST}}),
        {"op": "grant", "domain": "granted.dev"},
        {"op": "baseline_active_covers", "domain": "sub.example.com"},
        {"op": "baseline_active_covers", "domain": "x.sub.example.com"},
        {"op": "baseline_active_covers", "domain": "gone.org"},
        {"op": "baseline_active_covers", "domain": "granted.dev"},
        {"op": "baseline_active_covers", "domain": "nope.net"},
        {"op": "baseline_active_covers", "domain": "SUB.EXAMPLE.COM"},
    ]))
    c.append(_d("set_now moves the clock", [
        _cfg({"allow": ["a.com"], "expires": {"a.com": "2026-08-30T15:00:00+00:00"}}),
        *_inspect("a.com"),
        {"op": "set_now", "now": "2026-08-30T15:00:00+00:00"},
        *_inspect("a.com"),
        {"op": "grant", "domain": "b.com", "expires_at": FUTURE},
        {"op": "granted_entries"},
    ]))
    # Overlay contract.
    full = ("- domain: a.com\n  granted_at: '2026-08-30T14:00:00+00:00'\n"
            "  expires_at: ''\n  reason: r\n  source: decider\n")
    for label, text in [
        ("full entry", full),
        ("garbage", ":\n  - [\n"),
        ("not a list", "domain: a.com\n"),
        ("empty", ""),
        ("filters entries", "- domain: ''\n- 5\n- [a]\n- {reason: x}\n"
                            "- domain: ok.com\n- domain: null\n"),
        ("extra keys and odd values", "- domain: Up.COM.\n  extra: 1\n"
                                      "  expires_at: 7\n  note: [x, y]\n"),
    ]:
        c.append(_d(f"parse_overlay: {label}",
                    [{"op": "parse_overlay", "overlay": text}]))
    c.append(_d("reconcile", [
        _cfg({"allow": ["base.com"]}),
        {"op": "grant", "domain": "keep.com", "expires_at": FUTURE,
         "reason": "in memory"},
        {"op": "grant", "domain": "drop.com"},
        {"op": "reconcile", "overlay":
            "- domain: keep.com\n  granted_at: x\n  expires_at: ''\n"
            "  reason: on disk\n  source: host\n"
            "- domain: NEW.com.\n  granted_at: y\n  expires_at: '2000-01-01T00:00:00+00:00'\n"
            "  reason: added\n  source: host\n  extra: kept\n"
            "- domain: dup.com\n  reason: first\n"
            "- domain: dup.com\n  reason: second\n"},
        {"op": "granted_entries"},
        *_hosts("is_granted", "keep.com", "drop.com", "new.com", "dup.com"),
        *_inspect("new.com", "keep.com"),
        {"op": "drop_expired", "now_iso": NOW},
        {"op": "reconcile", "overlay": "garbage: ["},
        {"op": "granted_entries"},
    ]))
    return c


def _b(kind, name, config, *ctxs):
    return {"name": name, "inspector": kind, "steps": [
        {"op": "configure", "config": config},
        *({"op": "inspect", "ctx": c} for c in ctxs),
    ]}


def body_size_cases() -> list:
    k = "body-size"
    return [
        _b(k, "global cap", {"max_bytes": 100},
           ctx(body=b"x" * 200), ctx(body=b"x" * 100), ctx(body=b"x" * 101),
           ctx(body=None)),
        _b(k, "zero disables", {"max_bytes": 0}, ctx(body_size=10_000_000)),
        _b(k, "defaults: no cap", {}, ctx(body_size=10_000_000)),
        _b(k, "float cap prints as float", {"max_bytes": 100.5},
           ctx(body_size=101), ctx(body_size=100)),
        _b(k, "bool cap is one byte", {"max_bytes": True}, ctx(body_size=2)),
        _b(k, "host override raises", {"max_bytes": 100,
                                       "host_max_bytes": {"fcos-vm-home-01": 1000}},
           ctx(body_size=500, host="fcos-vm-home-01"),
           ctx(body_size=500, host="api.anthropic.com")),
        _b(k, "host override lowers", {"max_bytes": 1000,
                                       "host_max_bytes": {"strict.example.com": 100}},
           ctx(body_size=500, host="strict.example.com"),
           ctx(body_size=500, host="STRICT.example.com"),
           ctx(body_size=500, host="notstrict.example.com")),
        _b(k, "host override suffix and longest wins", {
            "max_bytes": 100,
            "host_max_bytes": {"ts.net": 10_000,
                               "paperless.taile1b309.ts.net": 500,
                               "Upper.Example": "300"}},
           ctx(body_size=1000, host="paperless.taile1b309.ts.net"),
           ctx(body_size=1000, host="x.paperless.taile1b309.ts.net"),
           ctx(body_size=1000, host="other.ts.net"),
           ctx(body_size=400, host="upper.example"),
           ctx(body_size=400, host="ts.net.evil")),
        _b(k, "host override zero disables for host", {
            "max_bytes": 100, "host_max_bytes": {"unlimited.example.com": 0}},
           ctx(body_size=10_000_000, host="unlimited.example.com"),
           ctx(body_size=101, host="example.com")),
        _b(k, "host override int() coercion", {
            "max_bytes": 100, "host_max_bytes": {"a.com": 50.9, "b.com": " 70 "}},
           ctx(body_size=60, host="a.com"), ctx(body_size=71, host="b.com")),
        _b(k, "bad host override value", {"host_max_bytes": {"a.com": "lots"}}),
    ]


def entropy_cases() -> list:
    k = "entropy"
    hi = noise(1024)
    hi_b64 = base64.urlsafe_b64encode(noise(128, "q")).decode()
    lo = b"hello world, this is a fairly ordinary sentence. " * 20
    pct = "".join(f"%{b:02X}" for b in noise(48, "p"))
    return [
        _b(k, "defaults", {},
           ctx(body=hi, text=None, content_type="application/octet-stream"),
           ctx(body=lo, content_type="text/plain"),
           ctx(body=hi[:255], text=None, content_type="application/x-foo"),
           ctx(body=hi, text=None, content_type="image/png"),
           ctx(body=hi, text=None, content_type="application/gzip"),
           ctx(body=hi, text=None, content_type="Image/png")),
        _b(k, "explicit entropy values", {"threshold": 7.0, "min_body_bytes": 64,
                                          "action": "flag"},
           ctx(body=hi, text=None, body_entropy=8.0, content_type="x/y"),
           ctx(body=hi, text=None, body_entropy=7.0, content_type="x/y"),
           ctx(body=hi, text=None, body_entropy=6.999, content_type="x/y"),
           ctx(body=hi, text=None, body_entropy=7.125, content_type="x/y"),
           ctx(body=hi, text=None, body_entropy=7.995, content_type="x/y"),
           ctx(body=hi[:63], text=None, body_entropy=8.0, content_type="x/y"),
           ctx(body=None, body_entropy=None)),
        _b(k, "int threshold prints as int", {"threshold": 7, "action": "block"},
           ctx(body=hi, text=None, content_type="x/y")),
        _b(k, "action flag", {"action": "flag"},
           ctx(body=hi, text=None, content_type="x/y")),
        _b(k, "custom exempt list replaces defaults", {
            "exempt_content_types": ["application/x-tar"]},
           ctx(body=hi, text=None, content_type="image/png"),
           ctx(body=hi, text=None, content_type="application/x-tar; x=1")),
        _b(k, "host exemptions", {
            "host_exempt_content_types": {"Matrix.Example.com": ["audio/", "video/"]}},
           ctx(body=hi, text=None, content_type="audio/ogg", host="matrix.example.com"),
           ctx(body=hi, text=None, content_type="audio/ogg", host="a.matrix.example.com"),
           ctx(body=hi, text=None, content_type="audio/ogg", host="other.com"),
           ctx(body=hi, text=None, content_type="application/x-tar",
               host="matrix.example.com")),
        _b(k, "url params", {"url_min_value_bytes": 32},
           ctx(url=f"https://github.com/search?q={hi_b64}&type=code",
               host="github.com"),
           ctx(url="https://github.com/search?q=agentcage+python&type=code",
               host="github.com"),
           ctx(url=f"https://github.com/search?Q%5Fx={hi_b64}", host="github.com"),
           ctx(url=f"https://github.com/s?a=short&b={hi_b64[:31]}&c={hi_b64[:40]}",
               host="github.com"),
           ctx(url=f"https://h.com/p?x&y=&z={hi_b64}#frag", host="h.com"),
           ctx(url=f"https://h.com/p?k={hi_b64}&k=again", host="h.com"),
           ctx(url=f"https://h.com/p#?k={hi_b64}", host="h.com")),
        _b(k, "url param percent and plus decoding", {"url_min_value_bytes": 16,
                                                       "check_url_path": False},
           ctx(url=f"https://h.com/p?v={pct}", host="h.com"),
           ctx(url="https://h.com/p?v=" + "%C3%28%E2%82%F0%9F%98a%ED%A0%80" * 4,
               host="h.com"),
           ctx(url="https://h.com/p?v=" + "a+b%2Bc%zz%4" * 6, host="h.com"),
           ctx(url="https://h.com/p?v=é%C3%A9" + hi_b64[:40], host="h.com")),
        _b(k, "url checks disabled", {"check_url_params": False, "check_url_path": 0,
                                      "url_min_value_bytes": 32},
           ctx(url=f"https://github.com/{hi_b64}?q={hi_b64}", host="github.com")),
        _b(k, "url path segments", {"url_min_value_bytes": 32},
           ctx(url=f"https://h.com/a/{hi_b64}/b", host="h.com"),
           ctx(url="https://h.com/api/v1/users/12345/repos", host="h.com"),
           ctx(url=f"https://h.com/a/{hi_b64[:31]}", host="h.com"),
           ctx(url=f"https://h.com/a/x;{hi_b64}", host="h.com"),
           ctx(url=f"https://h.com/a;{hi_b64}/b", host="h.com"),
           ctx(url=f"  https://h.com/\t{hi_b64}", host="h.com"),
           ctx(url=f"https://h.com/{pct}", host="h.com")),
        _b(k, "cdn allowlist defaults", {"url_min_value_bytes": 32},
           ctx(url=f"https://d1.cloudfront.net/f?Signature={hi_b64}&Policy={hi_b64}",
               host="d1.cloudfront.net"),
           ctx(url=f"https://d1.cloudfront.net/f?Other={hi_b64}",
               host="d1.cloudfront.net"),
           ctx(url=f"https://b.s3.amazonaws.com/k?x-amz-signature={hi_b64}",
               host="b.s3.amazonaws.com")),
        _b(k, "allowlist merge and wildcard", {
            "url_min_value_bytes": 32,
            "host_url_param_allowlist": {
                "googleapis.com": ["*"],
                "cloudfront.net": ["Custom"],
                "API.example.com": ["Token"],
            }},
           ctx(url=f"https://www.googleapis.com/x/{hi_b64}?pageToken={hi_b64}",
               host="www.googleapis.com"),
           ctx(url=f"https://d1.cloudfront.net/f?Signature={hi_b64}",
               host="d1.cloudfront.net"),
           ctx(url=f"https://d1.cloudfront.net/f?custom={hi_b64}",
               host="d1.cloudfront.net"),
           ctx(url=f"https://api.example.com/f?token={hi_b64}",
               host="api.example.com"),
           ctx(url=f"https://other.com/f?token={hi_b64}", host="other.com")),
        _b(k, "body wins over url", {"url_min_value_bytes": 32},
           ctx(url=f"https://h.com/p?q={hi_b64}", host="h.com", body=hi, text=None,
               content_type="x/y")),
        _b(k, "bad allowlist type", {"host_url_param_allowlist": ["x"]}),
    ]


def content_type_cases() -> list:
    k = "content-type"
    b64 = "ABCDEFGHIJKLMNOP" * 20
    return [
        _b(k, "entropy ceiling", {"entropy_ceiling": 6.5, "action": "flag"},
           ctx(content_type="application/json", body='{"k": "v"}', body_entropy=7.2),
           ctx(content_type="application/json", body='{"k": "v"}', body_entropy=6.5),
           ctx(content_type="application/json", body='{"k": "v"}', body_entropy=4.0),
           ctx(content_type="application/octet-stream", body="some data",
               body_entropy=7.9),
           ctx(content_type="", body="data", body_entropy=7.9),
           ctx(content_type="text/plain", body=None, body_entropy=7.9),
           ctx(content_type="TEXT/plain", body="x", body_entropy=7.9)),
        _b(k, "defaults block", {},
           ctx(content_type="multipart/form-data; boundary=x", body="x" * 10,
               body_entropy=6.6),
           ctx(content_type="text/plain", body=f"pre\n{b64}\npost"),
           ctx(content_type="text/plain", body=b64[:255]),
           ctx(content_type="text/plain", body=b64[:256])),
        _b(k, "int ceiling prints as int", {"entropy_ceiling": 6},
           ctx(content_type="text/csv", body="x", body_entropy=6.01)),
        _b(k, "base64 detection", {"detect_base64": True, "base64_min_len": 64,
                                   "action": "flag"},
           ctx(content_type="text/plain", body=f"some preamble\n{b64}\nsome postamble"),
           ctx(content_type="text/plain",
               body="preamble\n" + "ABCDEFgh-_" * 40 + "\npostamble"),
           ctx(content_type="application/json", body='{"data": "aGVsbG8="}'),
           ctx(content_type="text/plain", body="x" * 63 + "!"),
           ctx(content_type="text/plain", body="a" * 30 + "\n" + "b" * 40),
           ctx(content_type="text/plain", body="a" * 30 + "   \x1c" + "b" * 40),
           ctx(content_type="text/plain", body="abé" + "c" * 70 + "é"),
           ctx(content_type="text/plain", body="c" * 70 + "\r\n" + "!"),
           ctx(content_type="text/plain",
               body="!" + "c" * 70 + "\n" + "d" * 70 + "!")),
        _b(k, "base64 detection off", {"detect_base64": False},
           ctx(content_type="text/plain", body=b64)),
        _b(k, "host exemptions", {
            "host_exempt_content_types": {"Paperless.example.com": ["multipart/form-data"]}},
           ctx(content_type="multipart/form-data; b=1", body="x", body_entropy=7.8,
               host="paperless.example.com"),
           ctx(content_type="multipart/form-data; b=1", body="x", body_entropy=7.8,
               host="a.paperless.example.com"),
           ctx(content_type="multipart/form-data; b=1", body="x", body_entropy=7.8,
               host="other.com"),
           ctx(content_type="application/json", body="x", body_entropy=7.8,
               host="paperless.example.com")),
    ]


_FULL = {"domains": {"allow": ["example.com"]}}


def _chain(name, config, plugins=None):
    step = {"op": "build", "config": config}
    if plugins is not None:
        step["plugins"] = plugins
    return {"name": name, "inspector": "chain", "steps": [step]}


def chain_cases() -> list:
    d = "/etc/agentcage/inspectors/"
    p = {d + "my.wasm": "my-check", d + "other.wasm": "other-check",
         d + "sec.wasm": "secrets", d + "broken.wasm": None}
    my = d + "my.wasm"
    return [
        _chain("bare", {}),
        _chain("domains only", dict(_FULL)),
        _chain("legacy all on", {**_FULL, "entropy": {"threshold": 7.5},
                                 "max_request_body": 1000,
                                 "content_type": {"entropy_ceiling": 6.0},
                                 "secrets": {"action": "block"}}),
        _chain("legacy all off", {**_FULL, "content_type": False,
                                  "max_request_body": 0, "entropy": False}),
        _chain("legacy falsy spellings", {**_FULL, "content_type": 0,
                                          "max_request_body": None,
                                          "entropy": None}),
        _chain("content_type non-mapping truthy", {**_FULL, "content_type": "yes"}),
        _chain("section builtins append in section order", {**_FULL, "inspectors": [
            {"name": "entropy", "config": {"threshold": 6.5}},
            {"name": "body-size", "config": {"max_bytes": 50}},
        ], "max_request_body": 0}),
        _chain("section overrides legacy wholesale", {
            **_FULL, "content_type": {"entropy_ceiling": 7.0, "action": "flag"},
            "max_request_body": 0,
            "inspectors": [
                {"name": "content-type", "config": {"entropy_ceiling": 8.0}},
                {"name": "secrets", "config": {"action": "flag"}},
                {"name": "body-size", "config": {"max_bytes": 10}},
                {"name": "body-size", "config": {"max_bytes": 20}},
                {"name": "domain", "config": {"block": ["evil.com"]}},
            ]}),
        _chain("section entry without config", {**_FULL, "inspectors": [
            {"name": "content-type"}, {"name": "entropy"}]}),
        _chain("unknown entries warn", {**_FULL, "inspectors": [
            {"name": "nope"}, {"config": {}}, {"name": None},
            {"name": "entropy", "path": ""}]}),
        _chain("plugins", {**_FULL, "content_type": False, "inspectors": [
            {"name": "my-check", "path": my, "config": {"marker": "m"}},
            {"name": "entropy", "config": {}},
        ]}, p),
        _chain("plugin first then builtin", {**_FULL, "inspectors": [
            {"name": "my-check", "path": my},
            {"name": "content-type", "config": {"action": "flag"}},
        ]}, p),
        _chain("plugin declares another name", {**_FULL, "inspectors": [
            {"name": "listed", "path": d + "other.wasm", "config": {"a": 1}},
        ]}, p),
        _chain("plugin entry named like a slot only reconfigures it", {
            **_FULL, "inspectors": [
                {"name": "my-check", "path": my, "config": {"v": 1}},
                {"name": "my-check", "path": d + "broken.wasm", "config": {"v": 2}},
                {"name": "content-type", "path": d + "broken.wasm",
                 "config": {"threshold": 5}},
            ]}, p),
        _chain("plugin declaring a builtin name takes its config", {
            **_FULL, "inspectors": [
                {"name": "x", "path": d + "sec.wasm", "config": {"action": "block"}},
            ]}, p),
        _chain("plugin declared twice merges", {**_FULL, "inspectors": [
            {"name": "a", "path": my, "config": {"n": 1}},
            {"name": "b", "path": my, "config": {"n": 2}},
        ]}, p),
        _chain("plugin load failure fails the build", {**_FULL, "inspectors": [
            {"name": "x", "path": d + "broken.wasm"}]}, p),
        _chain("bad section config fails the build", {**_FULL, "inspectors": [
            {"name": "body-size", "config": {"host_max_bytes": {"a": "x"}}}]}),
        _chain("bad secrets pattern fails the build", {**_FULL, "secrets": {
            "extra_patterns": [{"name": "x", "pattern": "("}]}}),
        _chain("inspectors not a list fails", {**_FULL, "inspectors": {"name": "x"}}),
        _chain("inspectors falsy", {**_FULL, "inspectors": None}),
    ]


def whitespace_cases() -> list:
    return [{"name": "python whitespace", "inspector": "whitespace",
             "steps": [{"op": "isspace"}, {"op": "re_s"}]}]


def build() -> dict:
    cases = (domain_cases() + body_size_cases() + entropy_cases()
             + content_type_cases() + chain_cases() + whitespace_cases())
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
