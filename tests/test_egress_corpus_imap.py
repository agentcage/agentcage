"""The IMAP relay corpus (tests/fixtures/egress/imap.json) still matches
the Python relay it was recorded from.

The Rust relay asserts the same file; this keeps the corpus honest while
the Python exists. Regenerate with
``uv run python tests/fixtures/egress/gen/imap.py``.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / "tests" / "fixtures" / "egress" / "imap.json").read_text())

_spec = importlib.util.spec_from_file_location(
    "egress_gen_imap", ROOT / "tests" / "fixtures" / "egress" / "gen" / "imap.py",
)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)
m = gen.m


@pytest.mark.parametrize("case", CORPUS["literals"], ids=lambda c: repr(c["line"])[:40])
def test_literals(case):
    assert gen.literal_case(gen.dec(case["line"])) == case["literal"]


@pytest.mark.parametrize("case", CORPUS["mutf7"], ids=lambda c: c["name"] or "empty")
def test_mutf7(case):
    assert m._mutf7_decode(case["name"]) == case["decoded"]


def test_policy():
    for case in CORPUS["policy"]:
        audit = []
        relay = m.ImapRelay(gen.entry(case["policy"]), audit_log=audit.append,
                            log_allowed=case["log_allowed"])
        mailbox = None if case["mailbox"] is None else gen.dec(case["mailbox"])
        decision = relay._policy_check(gen.dec(case["line"]), mailbox=mailbox,
                                       utf8_names=case["utf8_names"])
        got = None if decision is None else {
            "tag": gen.enc(decision[0]), "reason": decision[1],
            "status": decision[2].decode(),
        }
        assert (got, audit) == (case["decision"], case["audit"]), case


def _filter_outputs(case):
    f = m._ResponseFilter(
        lambda t: m._capability_hidden(t, case["mode"], case["folder_lists"])
    )
    outs, error = [], None
    for op in case["ops"]:
        try:
            if op[0] == "feed":
                outs.append(gen.enc_out(f.feed(gen.dec(op[1]))))
            elif op[0] == "insert":
                outs.append(gen.enc_out(f.insert(gen.dec(op[1]))))
            else:
                outs.append(gen.enc_out(f.finish()))
        except m._UnfilterableResponse as e:
            error = str(e)
            break
    return outs, error


@pytest.mark.parametrize("case", CORPUS["filter"], ids=lambda c: c["name"])
def test_filter(case):
    assert _filter_outputs(case) == (case["outputs"], case["error"])


@pytest.mark.parametrize("case", CORPUS["sessions"], ids=lambda c: c["name"])
def test_session(case):
    stored = {k: v for k, v in case.items() if k != "expect"}
    assert asyncio.run(gen.run_session(stored)) == case["expect"]


def test_a_wrong_expectation_fails():
    """Mutation check: the comparison bites."""
    case = dict(CORPUS["filter"][0])
    case["outputs"] = list(case["outputs"])
    case["outputs"][0] = case["outputs"][0] + "x"
    assert _filter_outputs(case) != (case["outputs"], case["error"])
