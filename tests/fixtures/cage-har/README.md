# `cage har` fixtures

`cases.json` is **generated**. Do not hand-edit it.

```sh
uv run python scripts/gen-cage-har-fixture.py          # write
uv run python scripts/gen-cage-har-fixture.py --check  # fail if stale
```

## What it is

Twenty-six recordings of the real Python `agentcage cage har`, run against a
throwaway copy of PR A7's frozen 0.40.1 state
(`tests/fixtures/state-compat/0.40.1/`). Each case records the argument vector,
the setup it needed, the exit status, stdout, stderr, and — for the `-o` cases
— the file that was written.

## Why it is not the golden corpus

`tests/fixtures/golden/shared/har/` already pins the HAR *builder*: both views
and eight filters over a hand-written `capture.jsonl`, and
`rust/agentcage-core/tests/golden_har.rs` reproduces those five files byte for
byte. That corpus says nothing about the command, and the command is where the
remaining decisions live:

- **which file is read, out of which of the three state roots.** A `container`
  or `vm` cage keeps its capture at
  `$XDG_DATA_HOME/agentcage/<name>/capture/capture.jsonl`; an `apple-container`
  cage keeps it at `~/.config/agentcage/apple-container/<name>/logs/capture.jsonl`,
  a root that expands `~` directly and **ignores `XDG_CONFIG_HOME`**. Two cases
  here (`apple-container-root`, `apple-container-root-missing`) exist to make
  that split visible — the second one because the path it names in the error is
  the only place the choice is printed.
- **the rotated generation.** The capture writer rolls over at
  `capture.max_file_size` and keeps one previous file, `capture.jsonl.1`, which
  holds the *older* half. `rotated-generation-first` pins that it is read first;
  a reader that skipped it would silently shorten every export taken after a
  rollover, and nothing would say so.
- **a partially written line.** `truncated-tail-dropped` appends half a JSON
  object, which is what a capture file looks like when the addon is killed
  mid-write. The record is dropped and the export continues.
- **the serialization, which is not the corpus's.** `cli.py:3101` is
  `json.dumps(har, indent=2)` — Python dict order and `ensure_ascii=True` —
  while the corpus harness writes `sort_keys=True, ensure_ascii=False`. Both
  come out of the same value, so the corpus proves the builder and these cases
  prove the shipped bytes. Two cases (`corpus-capture-*`) plant the corpus's
  own `capture.jsonl` as a cage's, so the same five awkward records go through
  the command as well as through the builder.
- **every error path the Python reports itself**, with its exit status. There
  are three — no such cage, no capture file, and the v0.22 legacy gate — and
  the last exits **2**, not 1. The two paths the Python does *not* report (an
  unreadable capture file, an unwritable `-o` destination) end in a traceback
  there and cannot be recorded as a contract; `cage_har.rs` asserts those
  directly instead.

## The input is A7's, on purpose

The `capture.jsonl` files under A7's snapshot were written by the **Python**
capture addon for a deployed cage. That is exactly the file the Rust reader
meets on a real user's disk at cutover, which is the whole reason A7 exists.
The golden corpus's `_inputs/capture.jsonl` is hand-written to be awkward; this
one is ordinary, and a port has to handle both.

## Three things the recordings pin that are arguably bugs

They are recorded rather than fixed, because this is a port and a port that
improves behaviour is a port nobody can verify:

1. **`capture: enable_har: false` and "no capture yet" are the same error.**
   `capture-disabled` is a cage with capture switched off; the message it gets
   tells it to switch capture on, which is right, but the command never reads
   the config to find out — it only notices the file is absent. A cage whose
   capture *is* enabled but has not seen traffic gets the identical message.
2. **A missing `metadata.json` reads as a v0.21 cage.** `_ensure_v022_cage`
   defaults the stamp to `"0.0.0"`, which is below `(0, 22)`, so
   `no-metadata-reads-as-legacy` exits 2 and prints a migration procedure for a
   layout the cage may never have had.
3. **`--json-lines` suppresses the outbound secrets warning.**
   `json-lines-outbound-no-warning` asks for the wire view, which contains real
   injected API keys, and gets no warning at all — the guard in `cli.py` is
   `if view == "outbound" and not json_lines`.

## Scrubbing

Two substitutions, both re-expanded by the reader:

| token | stands for |
| :-- | :-- |
| `{HOME}` | the sandbox home the case ran under |
| `{VERSION}` | the package version, inside a HAR `creator` block only |

`{VERSION}` keeps a release from churning 60 KB of fixture. `{HOME}` is what
makes the error paths comparable at all: two of them print an absolute path.

## The setup vocabulary

Each case's `setup` is a list of operations applied to the copied home before
the run, so the Rust test builds the same world from this file rather than from
a second, hand-kept copy of it. Four operations, each with a home-relative
`path`:

| `op` | effect |
| :-- | :-- |
| `write` | create or replace the file with `text` |
| `append` | append `text` to the existing file |
| `remove` | delete the file |
| `copy` | copy the repo-relative `from` file into place |

## Where it is asserted

`rust/agentcage-cli/tests/cage_har.rs` replays every case against
`agentcage_cli::har` and compares all four outputs byte for byte.
`.github/workflows/rust.yml` runs the generator with `--check`, so a change to
`cli.py`'s `cage har` that this port has not followed fails CI rather than
quietly leaving the fixture behind.
