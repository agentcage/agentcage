"""``tests/fixtures/egress/injection.json`` still says what the Python does.

Every case is replayed through the Python egress's ``SecretInjector``
(and the ``configure`` and ``transform`` sections through ``configure``
and ``GoogleJwtBearer``) with the generator's flow surface
(``gen/injection.py``). The Rust port asserts the same file
(``rust/agentcage-egress/src/inject/tests.rs`` and ``transforms.rs``).
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

GEN = Path(__file__).parent / "fixtures" / "egress" / "gen" / "injection.py"
_spec = importlib.util.spec_from_file_location("egress_gen_injection", GEN)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

CORPUS = json.loads(gen.OUT.read_text())


def _replay(case) -> dict:
    return gen.run({k: v for k, v in case.items() if k != "expect"})


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["name"])
def test_case(case):
    assert _replay(case) == case


def test_configure():
    assert gen.configure_cases() == CORPUS["configure"]


def test_transform():
    assert gen.transform_section() == CORPUS["transform"]


def test_the_corpus_bites(monkeypatch):
    """A deliberately broken injector must disagree with the corpus."""
    # The globals of the module the generator's injector came from (other
    # tests may re-import it under another name).
    module = gen.SecretInjector.configure.__globals__
    monkeypatch.setitem(module, "_B64_MIN_BYTES", 10_000)
    assert any(_replay(c) != c for c in CORPUS["cases"])
    monkeypatch.undo()
    monkeypatch.setitem(module, "AUTH_HEADER_KEYWORDS", ("auth",))
    assert any(_replay(c) != c for c in CORPUS["cases"])
