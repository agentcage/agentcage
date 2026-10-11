"""``tests/fixtures/egress/get_text.json`` still says what the Python does.

Every case is recomputed with the generator's restatement of the body
decoding (``gen/get_text.py``) on this Python's codecs, zlib, brotli and
zstandard. The ``br`` / ``zstd`` cases need the two compression modules
the egress image installs and are skipped without them. The Rust port
asserts the same file (``rust/agentcage-egress/src/text.rs``).
"""

from __future__ import annotations

import codecs
import importlib.util
import json
from pathlib import Path

import pytest

GEN = Path(__file__).parent / "fixtures" / "egress" / "gen" / "get_text.py"
_spec = importlib.util.spec_from_file_location("egress_gen_get_text", GEN)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

CORPUS = json.loads(gen.OUT.read_text())


def _needs(case) -> str | None:
    name = case["name"]
    if name.startswith("encoding/br") and gen.brotli is None:
        return "brotli"
    if name.startswith("encoding/zstd") and gen.zstandard is None:
        return "zstandard"
    return None


def _replay(case) -> dict:
    return gen.run_case({
        "name": case["name"],
        "headers": case["headers"],
        "body": gen.dec_bytes(case["body"]),
    })


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: c["name"])
def test_case(case):
    module = _needs(case)
    if module:
        pytest.skip(f"needs {module}")
    assert _replay(case) == case


def test_labels():
    for entry in CORPUS["labels"]:
        try:
            name = codecs.lookup(entry["label"].lower()).name
        except (LookupError, ValueError):
            name = None
        assert name == entry["codec"], entry["label"]


def test_tables_and_multibyte():
    data = gen.build()
    assert data["tables"] == CORPUS["tables"]
    assert data["multibyte"] == CORPUS["multibyte"]


def test_the_corpus_bites(monkeypatch):
    """A deliberately wrong decoder must disagree with the corpus."""
    monkeypatch.setattr(gen, "_py_text", lambda text: text.upper())
    cases = [c for c in CORPUS["cases"] if not _needs(c)]
    assert any(_replay(c) != c for c in cases)
    monkeypatch.undo()
    monkeypatch.setattr(gen, "infer_content_encoding",
                        lambda content_type, content=b"": "utf8")
    assert any(_replay(c) != c for c in cases)
