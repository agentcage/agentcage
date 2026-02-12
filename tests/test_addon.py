"""Tests for the addon orchestrator (shannon_entropy + custom loader)."""

import os
import math
import tempfile
import textwrap

import pytest

from inspectors.util import shannon_entropy, load_inspector_from_file
from inspectors.base import Inspector, InspectionResult, InspectionContext


# ── shannon_entropy ──────────────────────────────────────


class TestShannonEntropy:
    def test_empty_bytes(self):
        assert shannon_entropy(b"") == 0.0

    def test_single_byte_repeated(self):
        # All same bytes → 0 entropy
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_two_equal_values(self):
        # 50/50 split → 1 bit of entropy
        data = b"\x00" * 500 + b"\x01" * 500
        assert abs(shannon_entropy(data) - 1.0) < 0.01

    def test_all_256_byte_values(self):
        # Perfect uniform distribution → 8.0 bits
        data = bytes(range(256))
        assert abs(shannon_entropy(data) - 8.0) < 0.01

    def test_english_text_in_range(self):
        text = b"The quick brown fox jumps over the lazy dog. " * 10
        entropy = shannon_entropy(text)
        assert 3.0 < entropy < 5.5

    def test_compressed_data_higher_entropy_than_text(self):
        import zlib
        text = b"Hello world! " * 1000
        compressed = zlib.compress(text)
        assert shannon_entropy(compressed) > shannon_entropy(text)


# ── load_inspector_from_file ────────────────────────────


class TestLoadInspectorFromFile:
    def test_loads_valid_inspector(self, tmp_path):
        code = textwrap.dedent("""\
            from inspectors.base import Inspector, InspectionResult, InspectionContext

            class TestInspector(Inspector):
                name = "test-inspector"

                def configure(self, config):
                    self.word = config.get("word", "BAD")

                def inspect_request(self, ctx):
                    if ctx.body_text and self.word in ctx.body_text:
                        return InspectionResult(
                            inspector=self.name,
                            action="block",
                            reason=f"found {self.word}",
                        )
                    return None
        """)
        p = tmp_path / "my_inspector.py"
        p.write_text(code)
        inspector = load_inspector_from_file(str(p), allowed_dirs=[str(tmp_path)])
        assert isinstance(inspector, Inspector)
        assert inspector.name == "test-inspector"

        inspector.configure({"word": "SECRET"})
        ctx = InspectionContext(
            url="https://example.com",
            host="example.com",
            method="POST",
            headers={},
            content_type="text/plain",
            body_bytes=b"contains SECRET data",
            body_text="contains SECRET data",
            body_size=20,
        )
        r = inspector.inspect_request(ctx)
        assert r is not None
        assert r.action == "block"
        assert "SECRET" in r.reason

    def test_raises_on_no_inspector_class(self, tmp_path):
        p = tmp_path / "empty.py"
        p.write_text("x = 1\n")
        with pytest.raises(ImportError, match="no Inspector subclass"):
            load_inspector_from_file(str(p), allowed_dirs=[str(tmp_path)])

    def test_raises_on_bad_path(self):
        with pytest.raises((ImportError, FileNotFoundError)):
            load_inspector_from_file("/nonexistent/path.py",
                                     allowed_dirs=["/nonexistent"])

    def test_rejects_path_outside_allowed_dirs(self, tmp_path):
        p = tmp_path / "evil.py"
        p.write_text("x = 1\n")
        with pytest.raises(ImportError, match="outside allowed directories"):
            load_inspector_from_file(str(p), allowed_dirs=["/etc/lobstercage/inspectors"])

    def test_rejects_symlink_escape(self, tmp_path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        real_file = outside / "evil.py"
        real_file.write_text("x = 1\n")
        link = allowed / "evil.py"
        link.symlink_to(real_file)
        with pytest.raises(ImportError, match="outside allowed directories"):
            load_inspector_from_file(str(link), allowed_dirs=[str(allowed)])
