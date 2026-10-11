"""The SMTP relay corpus (tests/fixtures/egress/smtp.json) still matches
the Python relay it was recorded from.

The Rust relay asserts the same file; this keeps the corpus honest while
the Python exists. Regenerate with
``uv run python tests/fixtures/egress/gen/smtp.py``.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / "tests" / "fixtures" / "egress" / "smtp.json").read_text())

_spec = importlib.util.spec_from_file_location(
    "egress_gen_smtp", ROOT / "tests" / "fixtures" / "egress" / "gen" / "smtp.py",
)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


@pytest.mark.parametrize("case", CORPUS["headers"], ids=lambda c: repr(c["body"])[:30])
def test_headers(case):
    got = gen.header_case(gen.dec(case["body"]))
    assert got == {"content_type": case["content_type"], "headers": case["headers"]}


@pytest.mark.parametrize("case", CORPUS["addresses"], ids=lambda c: c["arg"] or "empty")
def test_addresses(case):
    assert gen.m._extract_address(case["arg"]) == case["address"]


@pytest.mark.parametrize("case", CORPUS["sessions"], ids=lambda c: c["name"])
def test_session(case):
    stored = {k: v for k, v in case.items() if k != "expect"}
    assert asyncio.run(gen.run_session(stored)) == case["expect"]


def test_a_wrong_expectation_fails():
    """Mutation check: the comparison bites."""
    case = CORPUS["headers"][0]
    got = gen.header_case(gen.dec(case["body"]))
    assert got != {"content_type": "text/html", "headers": case["headers"]}
