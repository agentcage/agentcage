"""The LLM-wire oracle corpus still matches the Python egress.

``tests/fixtures/egress/llm_wire.json`` pins the request bytes the
decider/watcher LLM client sends and what it extracts from provider
replies, for the Rust port to reproduce. This re-runs each case against
the live Python, so the corpus cannot disagree with the implementation it
was recorded from while that implementation exists.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_CORPUS = _HERE / "fixtures" / "egress" / "llm_wire.json"
_GEN = _HERE / "fixtures" / "egress" / "gen" / "llm_wire.py"


def _gen():
    spec = importlib.util.spec_from_file_location("_gen_llm_wire", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_CASES = json.loads(_CORPUS.read_text())["cases"]


@pytest.fixture(scope="module")
def gen():
    return _gen()


def _same(a, b) -> bool:
    # NaN != NaN, so compare the serialised form.
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


@pytest.mark.parametrize("case", _CASES, ids=[c["id"] for c in _CASES])
def test_case_matches_the_python(gen, case):
    assert _same(gen.run(case), case["expected"])


def test_generator_and_corpus_list_the_same_cases(gen):
    assert [c["id"] for c in gen.cases()] == [c["id"] for c in _CASES]


def test_a_wrong_expectation_is_caught(gen):
    """Mutation sanity check: the comparison actually bites."""
    case = next(c for c in _CASES if c["kind"] == "request")
    mutated = json.loads(json.dumps(case["expected"]))
    mutated["body"] = mutated["body"].replace('": ', '":', 1)
    assert not _same(gen.run(case), mutated)
    case = next(c for c in _CASES if c["id"] == "openai-only-wrong-name")
    assert not _same(gen.run(case), {"args": {"decision": "grant"}})
