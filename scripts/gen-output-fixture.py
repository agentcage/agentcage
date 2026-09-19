#!/usr/bin/env python3
"""Generate the styling fixtures under tests/fixtures/output/.

``src/agentcage/output.py`` is the CLI's visible identity: every symbol,
every space and every SGR escape a user sees comes out of those eight
helpers. ``src/agentcage/_timing.py`` adds one more surface, the phase
table behind the hidden ``--timings`` flags. The golden corpus pins what
the CLI *says* (validation errors, warnings, render diagnostics); nothing
pins how it *looks*.

That matters for the Rust port (RUST-PORT-PLAN.md, Track D, PR D4),
because the port cannot import click. It has to re-emit click's escapes
by hand, and a wrong padding or a missing reset is invisible in review
and obvious to a user.

So this records the bytes. For each helper it drives the REAL Python --
including the real ``click.echo``, on a stream that claims to be a tty and
on one that does not -- and writes what came out. The expectations are
never typed; a case cannot be added with a wrong one.

Both modes are recorded because click's colour decision is not ours:
``click.style`` always emits escapes, and ``click.echo`` strips them again
when the destination stream is not a tty (``_compat.should_strip_ansi``:
``color`` is ``None``, no ``Context`` sets ``ctx.color``, so the answer is
``not isatty(stream)``). agentcage reads neither ``NO_COLOR`` nor
``FORCE_COLOR`` and has no global ``--color`` flag; ``cage audit
--no-color`` is per-command and does not reach this module. The recorded
pair is what makes the port's "colour only adds escapes" invariant
checkable.

Usage:
    uv run python scripts/gen-output-fixture.py          # write
    uv run python scripts/gen-output-fixture.py --check  # fail if stale

See tests/fixtures/output/README.md.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parent.parent
_OUT = _ROOT / "tests" / "fixtures" / "output"

sys.path.insert(0, str(_ROOT / "src"))

import click  # noqa: E402

from agentcage import _timing, output  # noqa: E402


class _TtyStringIO(io.StringIO):
    """A stream click believes is a terminal, so it keeps the escapes.

    click resolves colour from the destination stream and nothing else
    (see the module docstring), so claiming ``isatty()`` is the whole of
    what separates the two recorded modes.
    """

    def isatty(self) -> bool:
        return True


def _capture(fn, *, tty: bool) -> dict[str, str]:
    """Run *fn* with stdout/stderr swapped, and return what it wrote.

    ``output.py`` calls ``click.echo`` with no ``file=``, so click reaches
    for ``sys.stdout`` / ``sys.stderr`` at call time -- which is exactly
    what makes this capture the real thing rather than a re-rendering of
    it.
    """
    make = _TtyStringIO if tty else io.StringIO
    out, err = make(), make()
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        fn()
    finally:
        sys.stdout, sys.stderr = saved
    return {"out": out.getvalue(), "err": err.getvalue()}


# The dispatch table both sides share. A case names a function and its
# arguments; nothing on either side has to parse a call string, and a
# case for a function the Rust port has not written yet fails loudly
# instead of being silently skipped.
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


def _call_text(fn: str, args: list[str]) -> str:
    return f"{fn}({', '.join(repr(a) for a in args)})"


def _echo_case(cid: str, why: str, fn: str, *args: str) -> dict:
    """A helper that writes: record both streams, in both modes."""
    def run() -> None:
        _ECHO_FNS[fn](*args)

    color = _capture(run, tty=True)
    plain = _capture(run, tty=False)
    for stream in ("out", "err"):
        assert click.unstyle(color[stream]) == plain[stream], (
            f"{cid}: colour does more than add escapes to {stream}"
        )
    return {"id": cid, "why": why, "kind": "echo", "fn": fn,
            "args": list(args), "call": _call_text(fn, list(args)),
            "color": color, "plain": plain}


def _value_case(cid: str, why: str, fn: str, *args: str) -> dict:
    """A helper that returns a string: record it, and its stripped form.

    The styled form is what the Rust function must return; the stripped
    form is what the user sees once ``click.echo`` has been through it on
    a pipe.
    """
    value = _VALUE_FNS[fn](*args)
    return {"id": cid, "why": why, "kind": "value", "fn": fn,
            "args": list(args), "call": _call_text(fn, list(args)),
            "value": value, "unstyled": click.unstyle(value)}


# ── output.py ──────────────────────────────────────────────────


def _gen_styled() -> dict:
    cases: list[dict] = []
    c = cases.append

    # ── the three colour primitives ──
    c(_value_case("dim-ascii", "the dim wrapper, which every border and "
                  "label goes through", "dim", "borderline"))
    c(_value_case("dim-empty", "an empty string still gets the escapes: "
                  "click.style does not special-case it, and a port that "
                  "does would drift", "dim", ""))
    c(_value_case("dim-non-ascii", "the padding a port computes must be in "
                  "characters, not bytes", "dim", "caf\u00e9 \u2713"))
    c(_value_case("green", "the ok colour", "green", "ok"))
    c(_value_case("red", "the failure colour", "red", "no"))
    c(_value_case("nested-dim-of-green", "run.py composes these "
                  "(``step_done(dim(name))``), so the escapes nest and the "
                  "inner reset is NOT the outer one",
                  "dim", output.green("ok")))

    # ── banner_text: the width arithmetic ──
    for cid, ver, why in [
        ("banner-text-short", "0.0.0",
         "the shortest plausible version: the 44-column floor wins"),
        ("banner-text-release", "0.40.1",
         "the shipped version shape"),
        ("banner-text-at-the-floor", "0.40.1-" + "a" * 20,
         "title is exactly 42 characters, so max(len(title) + 2, 44) is a "
         "tie: the floor still applies and the padding is 2"),
        ("banner-text-over-the-floor", "0.40.1-" + "a" * 21,
         "one character more -- the first width that beats the floor. The "
         "border grows with the title and the padding stays 2, which is "
         "what a port that hard-codes 44 gets wrong"),
        ("banner-text-dev", "0.41.0.dev3+g1a2b3c4.d20260919",
         "a uv/hatch dev version, which is what a contributor sees"),
    ]:
        c(_value_case(cid, why, "banner_text", ver))

    # ── the echoing helpers ──
    c(_echo_case("banner", "banner() is banner_text() through click.echo, "
                 "which adds the trailing newline on top of the blank line "
                 "banner_text already ends with",
                 "banner", "0.40.1"))
    c(_echo_case("step-done", "the green tick line, on stdout",
                 "step_done", "Cage ready"))
    c(_echo_case("step-done-nested", "run.py's real call shape: a styled "
                 "argument inside a styled line",
                 "step_done", output.dim("web")))
    c(_echo_case("step-done-empty", "an empty message keeps the two leading "
                 "spaces and the trailing one", "step_done", ""))
    c(_echo_case("step-fail", "the red cross line, and it goes to STDERR -- "
                 "so on ``agentcage run > log`` it stays coloured while the "
                 "tick lines do not", "step_fail", "Build failed"))
    c(_echo_case("step-fail-non-ascii", "a message with a multi-byte "
                 "character", "step_fail", "cage \u2718 gone"))
    c(_echo_case("info-short-label", "the label is ljust(9), so a short "
                 "label is padded INSIDE the dim escapes",
                 "info", "Name", "web"))
    c(_echo_case("info-exact-label", "a label of exactly 9 characters: no "
                 "padding, and no separator either",
                 "info", "Endpoints", "none"))
    c(_echo_case("info-long-label", "ljust does not truncate, so a longer "
                 "label runs into the value with no space at all",
                 "info", "Provisioned", "yes"))
    c(_echo_case("info-empty-value", "the padding is still emitted",
                 "info", "Name", ""))
    c(_echo_case("separator", "the 44-column rule, which is the banner's "
                 "width floor and not a coincidence", "separator"))

    return {
        "fixture": "styled",
        "module": "agentcage.output",
        "summary": (
            "Every helper in output.py, recorded on a stream that claims "
            "to be a tty and on one that does not. click.style always "
            "emits the escapes; click.echo strips them again when the "
            "destination is not a terminal, and agentcage sets no "
            "ctx.color and reads no NO_COLOR, so that is the whole colour "
            "rule."
        ),
        "cases": cases,
    }


# ── output.Spinner ───────────────────────────────────────────


def _spin_for(msg: str, frames: int, *, tty: bool, pause: bool = False) -> dict:
    """Drive a real Spinner for exactly *frames* frames per thread.

    The spin loop paces itself with ``time.sleep``; replacing that with a
    counter that sets the loop's own stop Event makes the byte stream
    deterministic without touching the code under test. Each thread is
    joined before anything else writes, so nothing races the capture.
    """
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
            assert not thread.is_alive(), "the spin thread did not stop"

    def body() -> None:
        with patch.object(output.time, "sleep", fake_sleep):
            spinner = output.Spinner(msg)
            state["spinner"] = spinner
            with spinner:
                drain(spinner)
                if pause:
                    state["seen"] = 0  # re-arm for the resumed thread
                    spinner.pause()
                    spinner.resume()
                    drain(spinner)

    return _capture(body, tty=tty)


def _gen_spinner() -> dict:
    cases: list[dict] = []
    c = cases.append

    color = _spin_for("Starting cage...", 3, tty=True)
    plain = _spin_for("Starting cage...", 3, tty=False)
    c({
        "id": "spinner-tty-three-frames",
        "why": ("on a tty the spinner rewrites one line: carriage return, "
                "two spaces, a braille frame, the message -- then the "
                "context manager erases the line with \\r\\x1b[K. Three "
                "frames, because the frame sequence has to advance."),
        "kind": "echo",
        "fn": "spinner",
        "call": "with Spinner('Starting cage...'): ...  # 3 frames",
        "color": color,
        "plain": plain,
    })

    paused = _spin_for("Starting cage...", 2, tty=True, pause=True)
    c({
        "id": "spinner-tty-pause-resume",
        "why": ("pause() erases the line and stops the thread so a "
                "subprocess can own it; resume() starts a fresh thread on "
                "the SAME message. The extra \\r\\x1b[K is the pause."),
        "kind": "echo",
        "fn": "spinner",
        "call": "with Spinner(msg) as s: s.pause(); s.resume()",
        "color": paused,
        "plain": _spin_for("Starting cage...", 2, tty=False, pause=True),
    })

    non_tty = _spin_for("Stopping cage...", 1, tty=False)
    c({
        "id": "spinner-not-a-tty",
        "why": ("without a tty there is no thread and no animation at all: "
                "one static line with a horizontal ellipsis, and nothing on "
                "exit. This is what CI logs contain."),
        "kind": "echo",
        "fn": "spinner",
        "call": "with Spinner('Stopping cage...'): ...",
        "color": non_tty,
        "plain": non_tty,
    })

    return {
        "fixture": "spinner",
        "module": "agentcage.output.Spinner",
        "summary": (
            "The braille spinner's byte stream, with time.sleep replaced "
            "by a frame counter so the recording is deterministic. The "
            "frames themselves are recorded separately so a port can "
            "advance them in the same order."
        ),
        "frames": output.Spinner._FRAMES,
        "frame_interval_seconds": 0.08,
        "cases": cases,
    }


# ── _timing.py ───────────────────────────────────────────────


_FAKE_RECORDS = {
    "typical": [
        {"label": "lima.create", "ms": 41230.0, "ts": 1.0},
        {"label": "build.egress", "ms": 18880.5, "ts": 2.0},
        {"label": "deploy", "ms": 3410.25, "ts": 3.0},
    ],
    "long-label": [
        {"label": "lima.provision.podman.network", "ms": 900.0, "ts": 1.0},
        {"label": "x", "ms": 100.0, "ts": 2.0},
    ],
    "zero-total": [
        {"label": "instant", "ms": 0.0, "ts": 1.0},
    ],
    "rounding": [
        {"label": "half.up", "ms": 0.5, "ts": 1.0},
        {"label": "half.down", "ms": 1.5, "ts": 2.0},
        {"label": "third", "ms": 33.333, "ts": 3.0},
    ],
}


def _gen_timings() -> dict:
    cases: list[dict] = []
    c = cases.append

    for cid, records in _FAKE_RECORDS.items():
        def run(records=records) -> None:
            with patch.object(_timing, "load_latest",
                              lambda _cage: (Path("/fake.jsonl"), records)):
                _timing.print_summary("bench")
        c({
            "id": f"summary-{cid}",
            "why": {
                "typical": "a real cage-create shape: the label column is "
                           "at its 24-column floor and the percentages are "
                           "floored, not rounded",
                "long-label": "one label longer than 22 pushes the column "
                              "to len+2 and widens the rule with it",
                "zero-total": "a total of zero is replaced by 1.0 before "
                              "the division, so this prints 0% and not a "
                              "ZeroDivisionError",
                "rounding": "two exact .5 values: Python's format rounds "
                            "half to even, so 0.5 prints 0 and 1.5 prints 2",
            }[cid],
            "kind": "echo",
            "fn": "print_summary",
            "call": f"print_summary('bench')  # records={cid}",
            "records": records,
            "color": _capture(run, tty=True),
            "plain": _capture(run, tty=False),
        })

    def empty() -> None:
        with patch.object(_timing, "load_latest", lambda _cage: (None, [])):
            _timing.print_summary("bench")
    c({
        "id": "summary-no-data",
        "why": "the note goes to stderr, and nothing goes to stdout",
        "kind": "echo",
        "fn": "print_summary",
        "call": "print_summary('bench')  # no records",
        "records": [],
        "color": _capture(empty, tty=True),
        "plain": _capture(empty, tty=False),
    })

    # ── the Phase stderr echo ──
    for cid, elapsed_ms, why in [
        ("phase-echo", 1234.5678,
         "AGENTCAGE_TIMING=1 echoes one line per phase, to stderr, with "
         "the milliseconds rounded to an integer"),
        ("phase-echo-sub-millisecond", 0.4,
         "a phase faster than a millisecond still prints a line"),
    ]:
        def run(elapsed_ms=elapsed_ms) -> None:
            clock = iter([0.0, elapsed_ms / 1000.0])
            with patch.dict(os.environ, {"AGENTCAGE_TIMING": "1"}), \
                 patch.object(_timing.time, "perf_counter",
                              lambda: next(clock)):
                with _timing.Phase("build.egress"):
                    pass
        c({
            "id": cid,
            "why": why,
            "kind": "echo",
            "fn": "phase_echo",
            "call": f"with Phase('build.egress'): ...  # {elapsed_ms}ms",
            "label": "build.egress",
            "elapsed_ms": elapsed_ms,
            "color": _capture(run, tty=True),
            "plain": _capture(run, tty=False),
        })

    # ── the JSONL record ──
    ledger: list[dict] = []
    for cid, label, elapsed_ms, ts, why in [
        ("record-typical", "build.egress", 1234.5678, 1758283200.5,
         "the on-disk record: three keys in insertion order, ms rounded "
         "to two places"),
        ("record-trailing-zero", "deploy", 3410.5, 1758283201.0,
         "a float that is exactly representable still prints as a float, "
         "not an int -- json.dumps(3410.5) and json.dumps(1.0)"),
        ("record-sub-millisecond", "noop", 0.004, 1758283202.25,
         "round(ms, 2) can collapse to 0.0"),
    ]:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "run.jsonl"
            with patch.object(_timing, "_run_file", lambda _cage: path), \
                 patch.object(_timing.time, "time", lambda: ts):
                _timing._append("bench", label, elapsed_ms)
            ledger.append({
                "id": cid, "why": why, "kind": "jsonl", "fn": "ledger_line",
                "call": f"_append('bench', {label!r}, {elapsed_ms})",
                "label": label, "elapsed_ms": elapsed_ms, "ts": ts,
                "line": path.read_text(encoding="utf-8"),
            })
    cases.extend(ledger)

    return {
        "fixture": "timings",
        "module": "agentcage._timing",
        "summary": (
            "The phase table behind the hidden --timings flags, the "
            "AGENTCAGE_TIMING=1 stderr echo, and the JSONL record both "
            "implementations have to read back. Nothing here is styled, "
            "so the two modes agree -- which is itself worth pinning."
        ),
        "run_file_name_format": "%Y%m%dT%H%M%S-<pid>.jsonl (UTC)",
        "max_files_per_cage": _timing._MAX_FILES_PER_CAGE,
        "cases": cases,
    }


_GENERATORS = {
    "styled": _gen_styled,
    "spinner": _gen_spinner,
    "timings": _gen_timings,
}


def _render(doc: dict) -> str:
    # ensure_ascii so every escape, every braille frame and every box
    # character is visible as a \uXXXX in review instead of as bytes a
    # terminal would try to interpret.
    return json.dumps(doc, indent=2, ensure_ascii=True, sort_keys=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit non-zero if any fixture is out of date")
    args = ap.parse_args()

    assert threading.active_count() == 1, "a stray thread would race the capture"

    _OUT.mkdir(parents=True, exist_ok=True)
    stale = []
    for name, gen in sorted(_GENERATORS.items()):
        doc = gen()
        text = _render(doc)
        path = _OUT / f"{name}.json"
        if args.check:
            current = path.read_text() if path.exists() else ""
            if current != text:
                stale.append(path)
            print(f"{'STALE' if current != text else 'ok   '} {path.name} "
                  f"({len(doc['cases'])} cases)")
        else:
            path.write_text(text)
            print(f"wrote {path.relative_to(_ROOT)} ({len(doc['cases'])} cases)")

    if stale:
        print("\nOut of date. Regenerate with:\n"
              "    uv run python scripts/gen-output-fixture.py\n"
              "and read the diff -- every changed byte is something a user "
              "sees.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
