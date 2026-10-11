"""The Policy API oracle corpus still matches the Python egress.

``tests/fixtures/egress/policy_api.json`` pins the control-host router,
the request decision flow, the grants overlay, the sweeper and the DNS
publish — status, exact response bytes, audit records, files on disk and
the decider's request bodies — for the Rust port to reproduce. This
re-runs each case against the live Python, so the corpus cannot disagree
with the implementation it was recorded from while that implementation
exists.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_CORPUS = _HERE / "fixtures" / "egress" / "policy_api.json"
_GEN = _HERE / "fixtures" / "egress" / "gen" / "policy_api.py"


def _gen():
    spec = importlib.util.spec_from_file_location("_gen_policy_api", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_CASES = json.loads(_CORPUS.read_text())["cases"]


@pytest.fixture(scope="module")
def gen():
    return _gen()


def _norm(value):
    return json.loads(json.dumps(value))


@pytest.mark.parametrize("case", _CASES, ids=[c["id"] for c in _CASES])
def test_case_matches_the_python(gen, case):
    assert _norm(gen.run(case)) == case["expected"]


def test_generator_and_corpus_list_the_same_cases(gen):
    assert [c["id"] for c in gen.cases()] == [c["id"] for c in _CASES]


def test_a_wrong_expectation_is_caught(gen):
    """Mutation sanity check: the comparison actually bites."""
    case = next(c for c in _CASES if c["id"] == "grant-openrouter")
    mutated = json.loads(json.dumps(case["expected"]))
    mutated["steps"][0]["body"] = mutated["steps"][0]["body"].replace(
        '"ttl_seconds": 600', '"ttl_seconds": 601')
    assert _norm(gen.run(case)) != mutated
    mutated = json.loads(json.dumps(case["expected"]))
    mutated["llm_requests"][0]["body"] = \
        mutated["llm_requests"][0]["body"].replace("senior", "junior", 1)
    assert _norm(gen.run(case)) != mutated
