"""Replay tests/fixtures/egress/secrets.json against the Python egress.

The corpus is the oracle the Rust port (``rust/agentcage-egress``)
asserts; this keeps it from drifting from the implementation it was
recorded from while that still exists. Regenerate with
``uv run python tests/fixtures/egress/gen/secrets.py``.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_CORPUS = _ROOT / "tests" / "fixtures" / "egress" / "secrets.json"
_GEN = _ROOT / "tests" / "fixtures" / "egress" / "gen" / "secrets.py"


def _load_gen():
    spec = importlib.util.spec_from_file_location("_egress_gen_secrets", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_gen = _load_gen()
_CASES = json.loads(_CORPUS.read_text())["cases"]


@pytest.mark.parametrize("case", _CASES, ids=[c["name"] for c in _CASES])
def test_case_matches_python(case):
    got = _gen.run_case(copy.deepcopy(case))
    want = [step["expect"] for step in case["steps"]]
    assert got == want


def test_corpus_is_what_the_generator_writes():
    """A case added to the generator but not re-recorded fails here."""
    assert _gen.build()["cases"] == _CASES


def test_a_wrong_expectation_is_caught():
    """Mutation check: claiming a near miss matches must not replay."""
    case = copy.deepcopy(next(c for c in _CASES
                              if c["name"] == "pattern: brave glued before"))
    case["steps"][0]["expect"] = ["brave_api_key"]
    assert _gen.run_case(case) != [s["expect"] for s in case["steps"]]
