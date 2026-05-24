"""Unit tests for agentcage._timing."""

from __future__ import annotations

import json
import time

import pytest

from agentcage import _timing


@pytest.fixture
def patch_timing_dir(tmp_path, monkeypatch):
    """Redirect _DATA_DIR to tmp_path and clear the per-pid run-file cache."""
    monkeypatch.setattr(_timing, "_DATA_DIR", tmp_path / "data" / "agentcage")
    monkeypatch.setattr(_timing, "_run_files", {})
    return tmp_path


class TestPhase:
    def test_appends_jsonl_record(self, patch_timing_dir):
        with _timing.Phase("build.proxy", cage="bench"):
            pass
        path, records = _timing.load_latest("bench")
        assert path is not None
        assert len(records) == 1
        assert records[0]["label"] == "build.proxy"
        assert records[0]["ms"] >= 0
        assert "ts" in records[0]

    def test_records_elapsed_milliseconds(self, patch_timing_dir):
        with _timing.Phase("sleep.10ms", cage="bench"):
            time.sleep(0.01)
        _, records = _timing.load_latest("bench")
        assert records[0]["ms"] >= 8  # allow scheduler slop
        assert records[0]["ms"] < 200

    def test_all_phases_in_one_process_share_a_file(self, patch_timing_dir):
        with _timing.Phase("a", cage="bench"):
            pass
        with _timing.Phase("b", cage="bench"):
            pass
        path, records = _timing.load_latest("bench")
        assert len(records) == 2
        assert [r["label"] for r in records] == ["a", "b"]

    def test_per_cage_files_are_isolated(self, patch_timing_dir):
        with _timing.Phase("x", cage="one"):
            pass
        with _timing.Phase("y", cage="two"):
            pass
        _, one = _timing.load_latest("one")
        _, two = _timing.load_latest("two")
        assert [r["label"] for r in one] == ["x"]
        assert [r["label"] for r in two] == ["y"]

    def test_no_cage_skips_persistence(self, patch_timing_dir):
        with _timing.Phase("orphan", cage=None):
            pass
        # No cage dir created.
        assert not (patch_timing_dir / "data" / "agentcage").exists()

    def test_env_echoes_to_stderr(self, patch_timing_dir, monkeypatch, capsys):
        monkeypatch.setenv("AGENTCAGE_TIMING", "1")
        with _timing.Phase("show.me", cage="bench"):
            pass
        captured = capsys.readouterr()
        assert "[timing] show.me:" in captured.err

    def test_env_unset_is_silent(self, patch_timing_dir, monkeypatch, capsys):
        monkeypatch.delenv("AGENTCAGE_TIMING", raising=False)
        with _timing.Phase("quiet", cage="bench"):
            pass
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == ""

    def test_exception_does_not_suppress_record(self, patch_timing_dir):
        with pytest.raises(RuntimeError):
            with _timing.Phase("fails", cage="bench"):
                raise RuntimeError("boom")
        _, records = _timing.load_latest("bench")
        assert len(records) == 1
        assert records[0]["label"] == "fails"

    def test_file_io_failure_does_not_propagate(
        self, patch_timing_dir, monkeypatch
    ):
        # Force _append to fail; the Phase exit must still return cleanly.
        def boom(*_a, **_kw):
            raise OSError("disk full")

        monkeypatch.setattr(_timing, "_append", boom)
        # Should not raise.
        with _timing.Phase("safe", cage="bench"):
            pass


class TestLoadLatest:
    def test_returns_none_when_no_files(self, patch_timing_dir):
        path, records = _timing.load_latest("missing")
        assert path is None
        assert records == []

    def test_returns_most_recent_file(self, patch_timing_dir):
        d = _timing._timings_dir("bench")
        d.mkdir(parents=True)
        (d / "20200101T000000-1.jsonl").write_text(
            json.dumps({"label": "old", "ms": 1, "ts": 0}) + "\n"
        )
        (d / "20300101T000000-2.jsonl").write_text(
            json.dumps({"label": "new", "ms": 2, "ts": 0}) + "\n"
        )
        path, records = _timing.load_latest("bench")
        assert path.name == "20300101T000000-2.jsonl"
        assert records[0]["label"] == "new"

    def test_skips_malformed_lines(self, patch_timing_dir):
        d = _timing._timings_dir("bench")
        d.mkdir(parents=True)
        (d / "20200101T000000-1.jsonl").write_text(
            json.dumps({"label": "ok", "ms": 1, "ts": 0}) + "\n"
            + "not-json\n"
            + "\n"
            + json.dumps({"label": "ok2", "ms": 2, "ts": 0}) + "\n"
        )
        _, records = _timing.load_latest("bench")
        assert [r["label"] for r in records] == ["ok", "ok2"]


class TestPrintSummary:
    def test_prints_phase_table_with_total(self, patch_timing_dir, capsys):
        out: list[str] = []
        with _timing.Phase("a", cage="bench"):
            time.sleep(0.005)
        with _timing.Phase("b", cage="bench"):
            time.sleep(0.005)
        _timing.print_summary("bench", echo=out.append)
        joined = "\n".join(out)
        assert "Phase" in joined
        assert "a" in joined
        assert "b" in joined
        assert "Total" in joined
        # Total line ends with seconds in parens.
        assert "(0." in joined or "(1." in joined

    def test_handles_missing_records(self, patch_timing_dir):
        out: list[str] = []
        _timing.print_summary("missing", echo=lambda s, **kw: out.append(s))
        assert any("no timing data" in line for line in out)

    def test_percent_sums_to_100(self, patch_timing_dir):
        out: list[str] = []
        for label in ("a", "b", "c"):
            with _timing.Phase(label, cage="bench"):
                time.sleep(0.002)
        _timing.print_summary("bench", echo=out.append)
        # Find percentage cells (last column "%")
        pct_lines = [
            line for line in out
            if line.endswith("%") and "Phase" not in line and "Total" not in line
        ]
        assert len(pct_lines) == 3


class TestRotation:
    def test_keeps_last_n_files(self, patch_timing_dir, monkeypatch):
        monkeypatch.setattr(_timing, "_MAX_FILES_PER_CAGE", 3)
        d = _timing._timings_dir("bench")
        d.mkdir(parents=True)
        # Pre-populate 5 files older than the new run.
        for i in range(5):
            (d / f"2020010{i}T000000-{i}.jsonl").write_text("{}\n")
        # Trigger rotation via a Phase write.
        with _timing.Phase("trigger", cage="bench"):
            pass
        remaining = sorted(p.name for p in d.glob("*.jsonl"))
        assert len(remaining) == 3
        # The two oldest were trimmed; the newest (just written) is present.
        assert remaining[-1].endswith(".jsonl")
