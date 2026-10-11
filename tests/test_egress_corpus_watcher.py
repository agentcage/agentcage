"""The traffic-watcher oracle corpus agrees with the Python it was recorded from.

``tests/fixtures/egress/watcher.json`` is what the Rust egress's watcher is
tested against. While the Python egress still exists, every case is re-run
through it here, so the corpus can never drift from the implementation it
pins. Regenerate with ``uv run python tests/fixtures/egress/gen/watcher.py``.
"""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_CORPUS = _ROOT / "tests" / "fixtures" / "egress" / "watcher.json"
_GEN = _ROOT / "tests" / "fixtures" / "egress" / "gen" / "watcher.py"


def _load_gen():
    spec = importlib.util.spec_from_file_location("_egress_gen_watcher", _GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _load_gen()
CASES = json.loads(_CORPUS.read_text())["cases"]


def test_corpus_covers_every_kind():
    kinds = {c["kind"] for c in CASES}
    assert kinds == {
        "config", "redact_headers", "excerpt_body", "sample_capture",
        "template_path", "dedup_samples", "est_tokens", "fit_to_budget",
        "build_digest", "norm_finding", "is_never_revoke", "system_prompt",
        "review_tool", "tail",
    }


def test_corpus_inputs_match_the_generator():
    """The checked-in inputs are the generator's: no hand edits."""
    fresh = gen.cases()
    assert [(c["kind"], c["name"]) for c in fresh] == \
        [(c["kind"], c["name"]) for c in CASES]
    for got, want in zip(fresh, CASES):
        assert json.loads(json.dumps(got["input"])) == want["input"], want["name"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['kind']}:{c['name']}")
def test_case_matches_python(case):
    got = json.loads(json.dumps(gen.compute(case)))
    assert got == case["expected"]


def test_a_wrong_expectation_is_caught():
    """Mutation sanity: the comparison above actually bites."""
    case = copy.deepcopy(next(c for c in CASES if c["kind"] == "build_digest"))
    case["expected"]["totals"]["flows"] += 1
    assert json.loads(json.dumps(gen.compute(case))) != case["expected"]
