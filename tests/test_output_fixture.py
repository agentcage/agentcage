"""The styling fixtures vs. the Python that generated them.

``tests/fixtures/output/`` records what ``output.py`` and ``_timing.py``
actually write, in both colour modes, so the Rust port (RUST-PORT-PLAN.md
Track D, PR D4) has something to be held to that neither implementation
owns. This is the Python half of that: it re-runs each recorded call and
requires the bytes back.

Why that is not circular. The fixture is generated from this same code,
so on its own "Python matches the fixture" proves only that nothing moved
since the last regeneration — which is exactly the regression net this
module did not have before. The part that bites is the *other* reader:
``rust/agentcage-cli/tests/golden_output.rs`` asserts the same file from
an implementation that cannot import click. A change here that is not a
deliberate re-bless breaks one side or the other.

``TestColourIsAdditive`` is the load-bearing invariant, and it is the one
PR C5 learned the hard way on the ``cage audit`` table: colour must only
ever ADD escapes. The moment a coloured branch pads a column differently
from its plain twin, the two modes stop being the same layout and every
byte after that point is a lie.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import click
import pytest

from agentcage import _timing, output

_FIXTURES = Path(__file__).parent / "fixtures" / "output"
_ROOT = Path(__file__).parent.parent


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / f"{name}.json").read_text())


STYLED = _load("styled")
SPINNER = _load("spinner")
TIMINGS = _load("timings")
_ALL = {"styled": STYLED, "spinner": SPINNER, "timings": TIMINGS}


class _TtyStringIO(io.StringIO):
    """The one bit of state click's colour decision actually reads."""

    def isatty(self) -> bool:
        return True


def _capture(fn, *, tty: bool) -> dict[str, str]:
    make = _TtyStringIO if tty else io.StringIO
    out, err = make(), make()
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        fn()
    finally:
        sys.stdout, sys.stderr = saved
    return {"out": out.getvalue(), "err": err.getvalue()}


def _case(doc: dict, cid: str) -> dict:
    for case in doc["cases"]:
        if case["id"] == cid:
            return case
    raise AssertionError(f"no case {cid!r} in {doc['fixture']}")


def _ids(doc: dict, kind: str | None = None) -> list[str]:
    return [c["id"] for c in doc["cases"] if kind is None or c["kind"] == kind]


# ── output.py, dispatched by name ────────────────────────────
#
# The fixture names a function and its arguments; both readers look the
# call up in a table rather than parsing a string, so a case for a
# helper this file does not know about fails loudly instead of being
# quietly skipped. ``rust/agentcage-cli/tests/golden_output.rs`` has the
# same table.

_VALUE_FNS = {
    "dim": output.dim,
    "green": output.green,
    "red": output.red,
    "banner_text": output.banner_text,
}

_ECHO_FNS = {
    "banner": output.banner,
    "step_done": output.step_done,
    "step_fail": output.step_fail,
    "info": output.info,
    "separator": output.separator,
}


class TestStyledValues:
    @pytest.mark.parametrize("cid", _ids(STYLED, "value"))
    def test_matches(self, cid):
        case = _case(STYLED, cid)
        fn = _VALUE_FNS.get(case["fn"])
        assert fn is not None, f"untested helper {case['fn']!r}"
        assert fn(*case["args"]) == case["value"]

    def test_banner_width_floor_and_growth(self):
        """The recorded widths are a property, not five arbitrary strings.

        ``width = max(len(title) + 2, 44)``. The two cases around the tie
        are what catch a port that hard-codes the 44.
        """
        short = _case(STYLED, "banner-text-short")["unstyled"]
        floor = _case(STYLED, "banner-text-at-the-floor")["unstyled"]
        over = _case(STYLED, "banner-text-over-the-floor")["unstyled"]
        assert len(short.splitlines()[0]) == 46      # 44 rule + two corners
        assert len(floor.splitlines()[0]) == 46      # the tie, still 44
        assert len(over.splitlines()[0]) == 47       # one wider, exactly
        for banner in (short, floor, over):
            top, mid, bottom, blank = banner.split("\n")
            assert len(top) == len(mid) == len(bottom)
            assert blank == ""
            assert mid.endswith("  \u2502"), "the padding is 2 at the tie"


class TestStyledEchoes:
    @pytest.mark.parametrize("cid", _ids(STYLED, "echo"))
    def test_both_modes(self, cid):
        case = _case(STYLED, cid)
        fn = _ECHO_FNS.get(case["fn"])
        assert fn is not None, f"untested helper {case['fn']!r}"

        def run():
            fn(*case["args"])

        assert _capture(run, tty=True) == case["color"]
        assert _capture(run, tty=False) == case["plain"]

    def test_step_fail_is_the_only_one_on_stderr(self):
        """Which stream a helper picks is behaviour, not decoration."""
        for cid in _ids(STYLED, "echo"):
            case = _case(STYLED, cid)
            on_stderr = bool(case["color"]["err"])
            assert on_stderr == (case["fn"] == "step_fail"), cid


# ── the invariant ────────────────────────────────────────────


class TestColourIsAdditive:
    """Stripping the escapes from a coloured run must give the plain run.

    If this ever fails, the two modes are no longer the same layout and
    the fixture's `plain` half has stopped describing what a pipe sees.
    """

    @pytest.mark.parametrize("name", ["styled", "timings"])
    def test_every_recorded_case(self, name):
        for case in _ALL[name]["cases"]:
            if case["kind"] == "value":
                assert click.unstyle(case["value"]) == case["unstyled"], case["id"]
            elif case["kind"] == "echo":
                for stream in ("out", "err"):
                    assert click.unstyle(case["color"][stream]) == \
                        case["plain"][stream], f"{case['id']}/{stream}"

    def test_the_spinner_emits_no_colour_at_all(self):
        """The spinner is the one place the two modes legitimately differ.

        Not by styling -- by behaviour: without a tty it prints one
        static line instead of animating. So the additive invariant does
        not apply, and what replaces it is that the spinner never emits
        an SGR sequence in the first place. The only escape it writes is
        ``\x1b[K``, an erase-to-end-of-line.
        """
        for case in SPINNER["cases"]:
            for stream in ("out", "err"):
                for mode in ("color", "plain"):
                    text = case[mode][stream]
                    assert text.replace("\x1b[K", "").find("\x1b") == -1, \
                        f"{case['id']}/{mode}/{stream}"

    def test_timing_output_is_never_styled(self):
        """_timing prints a table, not a styled one. Keep it that way."""
        for case in TIMINGS["cases"]:
            if case["kind"] != "echo":
                continue
            assert case["color"] == case["plain"], case["id"]
            assert "\x1b" not in case["color"]["out"] + case["color"]["err"]


# ── output.Spinner ───────────────────────────────────────────


def _spin(msg: str, frames: int, *, tty: bool, pause: bool = False) -> dict:
    state: dict = {"spinner": None, "seen": 0}

    def fake_sleep(_seconds: float) -> None:
        state["seen"] += 1
        spinner = state["spinner"]
        if spinner is not None and state["seen"] >= frames:
            spinner._stop.set()

    def drain(spinner: output.Spinner) -> None:
        thread = spinner._thread
        if thread is not None:
            thread.join(5)
            assert not thread.is_alive()

    def body() -> None:
        with patch.object(output.time, "sleep", fake_sleep):
            spinner = output.Spinner(msg)
            state["spinner"] = spinner
            with spinner:
                drain(spinner)
                if pause:
                    state["seen"] = 0
                    spinner.pause()
                    spinner.resume()
                    drain(spinner)

    return _capture(body, tty=tty)


class TestSpinner:
    def test_three_frames(self):
        case = _case(SPINNER, "spinner-tty-three-frames")
        assert _spin("Starting cage...", 3, tty=True) == case["color"]
        assert _spin("Starting cage...", 3, tty=False) == case["plain"]

    def test_pause_resume(self):
        case = _case(SPINNER, "spinner-tty-pause-resume")
        assert _spin("Starting cage...", 2, tty=True, pause=True) == case["color"]

    def test_not_a_tty(self):
        case = _case(SPINNER, "spinner-not-a-tty")
        assert _spin("Stopping cage...", 1, tty=False) == case["color"]

    def test_frames_are_recorded_in_order(self):
        assert SPINNER["frames"] == output.Spinner._FRAMES
        first_three = SPINNER["frames"][:3]
        err = _case(SPINNER, "spinner-tty-three-frames")["color"]["err"]
        written = [chunk for chunk in err.split("\r") if chunk.startswith("  ")]
        assert [chunk[2] for chunk in written] == list(first_three)


# ── _timing.py ───────────────────────────────────────────────


class TestTimings:
    @pytest.mark.parametrize("cid", [c for c in _ids(TIMINGS, "echo")
                                     if c.startswith("summary-")])
    def test_summary(self, cid):
        case = _case(TIMINGS, cid)
        records = case["records"]
        latest = (Path("/fake.jsonl"), records) if records else (None, [])

        def run() -> None:
            with patch.object(_timing, "load_latest", lambda _cage: latest):
                _timing.print_summary("bench")

        assert _capture(run, tty=False) == case["plain"]

    @pytest.mark.parametrize("cid", [c for c in _ids(TIMINGS, "echo")
                                     if c.startswith("phase-echo")])
    def test_phase_echo(self, cid, monkeypatch):
        case = _case(TIMINGS, cid)
        monkeypatch.setenv("AGENTCAGE_TIMING", "1")
        clock = iter([0.0, case["elapsed_ms"] / 1000.0])

        def run() -> None:
            with patch.object(_timing.time, "perf_counter", lambda: next(clock)):
                with _timing.Phase("build.egress"):
                    pass

        assert _capture(run, tty=False) == case["plain"]

    @pytest.mark.parametrize("cid", _ids(TIMINGS, "jsonl"))
    def test_ledger_line(self, cid, tmp_path):
        case = _case(TIMINGS, cid)
        path = tmp_path / "run.jsonl"
        with patch.object(_timing, "_run_file", lambda _cage: path), \
             patch.object(_timing.time, "time", lambda: case["ts"]):
            _timing._append("bench", case["label"], case["elapsed_ms"])
        assert path.read_text(encoding="utf-8") == case["line"]

    def test_rotation_constant_is_recorded(self):
        assert TIMINGS["max_files_per_cage"] == _timing._MAX_FILES_PER_CAGE


# ── fixture hygiene ──────────────────────────────────────────


class TestFixtureIntegrity:
    @pytest.mark.parametrize("name", sorted(_ALL))
    def test_shape(self, name):
        doc = _ALL[name]
        assert doc["fixture"] == name
        assert doc["summary"].strip()
        assert doc["cases"], "an empty fixture asserts nothing"
        for case in doc["cases"]:
            assert case["why"].strip(), f"{case['id']} has no rationale"
            assert case["kind"] in {"echo", "value", "jsonl"}
            assert case["fn"], f"{case['id']} names no function"

    @pytest.mark.parametrize("name", sorted(_ALL))
    def test_ids_are_unique(self, name):
        ids = _ids(_ALL[name])
        assert len(ids) == len(set(ids)), "case ids are the diff's anchors"

    @pytest.mark.parametrize("name", sorted(_ALL))
    def test_is_ascii_escaped_json(self, name):
        raw = (_FIXTURES / f"{name}.json").read_bytes()
        assert raw.isascii(), (
            "a braille frame or a box-drawing character written raw is "
            "unreviewable; keep ensure_ascii"
        )
        assert raw.endswith(b"\n")
        assert json.loads(raw.decode()) == _ALL[name]

    def test_generator_output_is_current(self):
        """Hand-editing a fixture is the failure mode this guards."""
        proc = subprocess.run(
            [sys.executable, str(_ROOT / "scripts" / "gen-output-fixture.py"),
             "--check"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0, (
            f"output fixtures are out of date:\n{proc.stdout}{proc.stderr}"
        )
