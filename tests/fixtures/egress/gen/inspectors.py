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

import json
import os
import sys
import tempfile
import types
from datetime import datetime as _real_datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[4]
_OUT = _ROOT / "tests" / "fixtures" / "egress" / "inspectors.json"

for _p in (_ROOT / "src" / "agentcage" / "data" / "proxy", _ROOT / "tests"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# The pytest conftest stubs the proxy framework the addon modules import
# at top level, so they load on a machine without it.
import conftest  # noqa: E402,F401

import inspectors.domain as _domain_mod  # noqa: E402
import policy_api as _policy_api  # noqa: E402
import watcher as _watcher  # noqa: E402
from inspectors.domain import DomainInspector  # noqa: E402

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


def _verdict(r):
    if r is None:
        return None
    return {
        "inspector": r.inspector,
        "action": r.action,
        "reason": r.reason,
        "severity": r.severity,
    }


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
        ctx = InspectionContext(
            url=f"https://{step['host']}/", host=step["host"], method="GET",
            headers=[], content_type="", body_bytes=None, body_text=None,
            body_size=0,
        )
        return _verdict(dom.inspect_request(ctx))
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


def run_case(case: dict) -> list:
    """Run one case; return the per-step results, in order."""
    if case["inspector"] != "domain":
        raise ValueError(f"unknown inspector {case['inspector']!r}")
    _pin_now(case["now"])
    try:
        dom = DomainInspector()
        return [_domain_step(dom, step) for step in case["steps"]]
    finally:
        _unpin()


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


def build() -> dict:
    cases = domain_cases()
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
