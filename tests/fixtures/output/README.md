# Output styling fixtures

Everything in this directory except this file is **generated**. Do not hand-edit it.

```sh
uv run python scripts/gen-output-fixture.py
uv run python scripts/gen-output-fixture.py --check   # what CI runs
```

## What it is

The golden corpus (`tests/fixtures/golden/`) pins what the CLI **says** — every
validation error, every warning, the renderer's stderr. Nothing pinned what it
**looks like**: the box-drawing banner, the green tick, the dim label column,
the braille spinner, the phase table. Those are eight helpers in
`src/agentcage/output.py` and one in `src/agentcage/_timing.py`, and between
them they are the entire visible identity of `agentcage`.

The Rust port (RUST-PORT-PLAN.md, Track D, PR D4) cannot import click. It
re-emits the escapes by hand, which makes a missing reset or an off-by-one
padding both invisible in review and immediately obvious to a user. So this
records the bytes, from the real Python, and the port is held to them.

| File | Covers |
| :-- | :-- |
| `styled.json` | `banner_text`, `banner`, `step_done`, `step_fail`, `info`, `separator`, `dim`, `green`, `red` |
| `spinner.json` | `output.Spinner` — frames, pause/resume, the non-tty fallback |
| `timings.json` | `_timing.print_summary`, the `AGENTCAGE_TIMING=1` echo, the JSONL record |

## Both colour modes, and why that is the whole colour rule

Every `echo` case is recorded twice: once with `sys.stdout` / `sys.stderr`
swapped for a stream that answers `isatty()` with `True`, once with one that
does not. That single difference is genuinely all there is to agentcage's
colour decision:

* `click.style` **always** emits the escapes. It does not look at anything.
* `click.echo` strips them again when the destination stream is not a
  terminal — `click._compat.should_strip_ansi` with `color=None` and no
  `Context` setting `ctx.color` reduces to `not isatty(stream)`.
* agentcage never passes `color=` to `echo`, never sets `ctx.color`, and
  reads neither `NO_COLOR` nor `FORCE_COLOR` (click 8.4 does not either).
  `cage audit --no-color` is a per-command flag threaded into
  `audit.format_table_row`; it does not reach `output.py`.

Two consequences the port has to keep:

* The decision is **per stream**. `step_fail` echoes to stderr, so
  `agentcage run > log` keeps the red cross and loses the green ticks.
* Colour **only adds escapes**. The generator asserts
  `click.unstyle(color) == plain` for every case before writing it, so the
  fixture cannot record a case where the two modes differ in layout. That is
  the same invariant PR C5 pinned for the `cage audit` table after the
  coloured branch was found padding a column differently.

## Determinism

The spinner and the phase ledger are the only moving parts, and both are
pinned rather than sampled:

* `time.sleep` is replaced, inside the spinner's own module, by a counter that
  sets the spin loop's `threading.Event` after N frames. The loop, the frame
  order and the writes are the real ones; only the pacing is fake. Every
  thread is joined before the capture is read.
* `time.perf_counter` and `time.time` are pinned for the `Phase` cases, so the
  recorded milliseconds and the `ts` field are fixed.

`scripts/gen-output-fixture.py --check` is byte-identical on CPython 3.12,
3.13 and 3.14 (verified). Nothing here goes through a pretty-printer that
ships with the interpreter, which is the trap documented in the golden
corpus's README.

## Shape

```json
{
  "fixture": "styled",
  "module": "agentcage.output",
  "summary": "…",
  "cases": [
    {"id": "step-fail", "why": "…", "kind": "echo", "call": "step_fail('Build failed')",
     "color": {"out": "", "err": "  \u001b[31m✗\u001b[0m Build failed\n"},
     "plain": {"out": "", "err": "  ✗ Build failed\n"}},

    {"id": "dim-ascii", "why": "…", "kind": "value", "call": "dim('borderline')",
     "value": "\u001b[2mborderline\u001b[0m", "unstyled": "borderline"}
  ]
}
```

`kind` is `echo` for a helper that writes (both streams are recorded, because
which one it picks is part of the behaviour), `value` for one that returns a
string, and `jsonl` for a `_timing` ledger line.

The files are ASCII-escaped JSON so that a braille frame, a box-drawing
character and an SGR escape all survive an editor, a diff viewer and a
terminal intact — and so a reviewer can see the difference between `─`
and `━`.

## Who reads them

* `tests/test_output_fixture.py` — asserts the Python still produces this, and
  that the generator is not stale.
* `rust/agentcage-cli/tests/golden_output.rs` — asserts the port reproduces
  every case, byte for byte, in both modes.

## Re-blessing

Deliberate, never reflexive. A failure means either a regression or an
intended change to what a user sees. Regenerate, then read the diff: a
one-symbol change should be a one-line diff.
