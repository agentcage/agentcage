#!/usr/bin/env python3
"""Generate the `cage har` fixtures under tests/fixtures/cage-har/.

``cage har`` is the one command whose *body* is almost entirely already
ported: ``agentcage_core::har`` (PR C6) reproduces the HAR builder and is
held byte-for-byte to ``tests/fixtures/golden/shared/har/``. What C6's
corpus cannot cover is the command around it — which file is read, from
which of the three state roots, what the filters do to it, what is
written where, and what every error path says.

So this generator runs the **real** ``agentcage cage har`` against a
throwaway copy of PR A7's frozen 0.40.1 state
(``tests/fixtures/state-compat/0.40.1/``) and records stdout, stderr, the
exit status and any ``-o`` output file, verbatim. A7's snapshot is the
right input for exactly the reason A7 exists: its ``capture.jsonl`` files
were written by the Python, which is what the Rust reader meets at
cutover.

Two of the three cages in that snapshot matter here and they disagree
about where the capture lives:

    acme-agent   isolation: container       $XDG_DATA_HOME/agentcage/<name>/capture/
    mac-agent    isolation: apple-container ~/.config/agentcage/apple-container/<name>/logs/
    plain-cage   isolation: container       — no capture file at all

The second of those expands ``~`` directly and ignores
``XDG_CONFIG_HOME``. The sandbox here therefore puts both XDG trees under
one ``HOME`` (the same arrangement ``tests/state_compat.rs`` uses), so the
apple root lands inside it rather than in the author's real home.

Each case declares the mutations it needs as data — a tiny
write/append/remove/copy vocabulary applied to the copied home — so the
Rust test builds the same world from the same file rather than from a
second, hand-kept copy of it.

Paths are scrubbed: the sandbox home becomes ``{HOME}`` and the package
version inside a HAR ``creator`` block becomes ``{VERSION}``, both
re-expanded by the reader.

Usage:
    uv run python scripts/gen-cage-har-fixture.py          # write
    uv run python scripts/gen-cage-har-fixture.py --check  # fail if stale

See tests/fixtures/cage-har/README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_OUT = _ROOT / "tests" / "fixtures" / "cage-har"
_STATE_FIXTURE = _ROOT / "tests" / "fixtures" / "state-compat" / "0.40.1"

# The cages A7 froze, by the name this file uses for them.
RICH = "acme-agent"
APPLE = "mac-agent"
MINIMAL = "plain-cage"

# Where the two capture files live inside the copied home, as the reader
# has to resolve them.
RICH_CAPTURE = f".local/share/agentcage/{RICH}/capture/capture.jsonl"
APPLE_CAPTURE = f".config/agentcage/apple-container/{APPLE}/logs/capture.jsonl"
MINIMAL_METADATA = f".config/agentcage/cages/{MINIMAL}/metadata.json"

# The golden corpus's hand-written capture, planted as a cage's own. Its
# five records are deliberately awkward where A7's two are ordinary.
CORPUS_CAPTURE = "tests/fixtures/golden/_inputs/capture.jsonl"

# The extra generation a rollover leaves behind. `capture.max_file_size`
# keeps one, and `cli.py` reads it FIRST because it holds the older half.
ROTATED_LINE = json.dumps(
    {
        "ts": "2026-03-14T15:00:00+00:00",
        "flow_id": "fixture-rotated-0001",
        "direction": "outbound",
        "decision": "allowed",
        "host": "rotated.example",
        "method": "GET",
        "path": "/older",
        "inspectors": [],
        "inbound": {
            "request": {
                "method": "GET",
                "url": "https://rotated.example/older",
                "httpVersion": "HTTP/1.1",
                "headers": [["host", "rotated.example"]],
                "body": "",
                "bodyEncoding": None,
                "bodySize": 0,
            },
            "response": {
                "status": 204,
                "statusText": "No Content",
                "httpVersion": "HTTP/1.1",
                "headers": [],
                "body": "",
                "bodyEncoding": None,
                "bodySize": 0,
                "mimeType": "",
            },
        },
        "outbound": {"request": {}, "response": {}},
    }
) + "\n"

# A writer killed mid-line. The reader must drop the partial record and
# keep everything before it, not abort the export.
TRUNCATED_TAIL = '{"ts": "2026-03-14T16:00:00+00:00", "flow_id": "fixture-tr'


def _write(path: str, text: str) -> dict:
    return {"op": "write", "path": path, "text": text}


def _append(path: str, text: str) -> dict:
    return {"op": "append", "path": path, "text": text}


def _remove(path: str) -> dict:
    return {"op": "remove", "path": path}


def _copy(source: str, path: str) -> dict:
    """Plant a file the repository already ships, by repo-relative path.

    Used for the golden corpus's own ``capture.jsonl``: embedding 4.5 KB
    of it in this fixture would be a second copy to keep in step, and a
    second copy is exactly what the corpus exists to avoid.
    """
    return {"op": "copy", "from": source, "path": path}


def _legacy_metadata(version: str) -> dict:
    """`plain-cage`'s metadata.json with its version stamp rewritten.

    Read from the fixture rather than typed out, so a regenerated A7
    snapshot carries through instead of silently disagreeing.
    """
    source = _STATE_FIXTURE / "xdg-config" / "agentcage" / "cages" / MINIMAL / "metadata.json"
    meta = json.loads(source.read_text())
    meta["agentcage_version"] = version
    return _write(MINIMAL_METADATA, json.dumps(meta))


def cases() -> list[dict]:
    """Every case, in the order the fixture records them.

    `argv` is what follows `agentcage`. `{HOME}` in an argument is
    expanded to the sandbox home before the run, which is how the `-o`
    case gets a writable destination that still scrubs.
    """
    return [
        # ── the two views, over a real Python-written capture ──
        {
            "name": "inbound-default",
            "why": "The default view and the default everything else.",
            "argv": ["cage", "har", RICH],
        },
        {
            "name": "outbound-view",
            "why": "The other perspective, and the stderr warning that guards it.",
            "argv": ["cage", "har", RICH, "--view", "outbound"],
        },
        # ── the backend split ──
        {
            "name": "apple-container-root",
            "why": (
                "An apple-container cage reads ~/.config/agentcage/"
                "apple-container/<name>/logs/, not the data root."
            ),
            "argv": ["cage", "har", APPLE],
        },
        {
            "name": "apple-container-root-missing",
            "why": "The path named in the error is the apple root, not the data root.",
            "argv": ["cage", "har", APPLE],
            "setup": [_remove(APPLE_CAPTURE)],
            "exit": 1,
        },
        # ── the raw passthrough ──
        {
            "name": "json-lines",
            "why": "`json.dumps(entry)` per line — separators and all.",
            "argv": ["cage", "har", RICH, "--json-lines"],
        },
        {
            "name": "json-compat-alias",
            "why": "The hidden `--json` spelling must reach the same code.",
            "argv": ["cage", "har", RICH, "--json"],
        },
        {
            "name": "json-lines-outbound-no-warning",
            "why": "The secrets warning is suppressed for --json-lines. It should not be.",
            "argv": ["cage", "har", RICH, "--view", "outbound", "--json-lines"],
        },
        # ── the filters, over the same two entries ──
        {
            "name": "filter-decision-blocked",
            "why": "-d blocked keeps one of the two.",
            "argv": ["cage", "har", RICH, "-d", "blocked"],
        },
        {
            "name": "filter-host-substring",
            "why": "--host is a substring match, not an equality test.",
            "argv": ["cage", "har", RICH, "--host", "telemetry"],
        },
        {
            "name": "filter-method-lowercase",
            "why": "--method is case-insensitive.",
            "argv": ["cage", "har", RICH, "--method", "post"],
        },
        {
            "name": "filter-direction-empty",
            "why": "A filter that matches nothing still produces a valid HAR log.",
            "argv": ["cage", "har", RICH, "--direction", "inbound"],
        },
        {
            "name": "filter-since-iso-keeps-all",
            "why": "An ISO --since before both timestamps.",
            "argv": ["cage", "har", RICH, "--since", "2026-03-14T15:00:00+00:00"],
        },
        {
            "name": "filter-since-iso-keeps-none",
            "why": "An ISO --since after both.",
            "argv": ["cage", "har", RICH, "--since", "2026-03-14T16:00:00+00:00"],
        },
        {
            "name": "max-entries-keeps-last",
            "why": "-n keeps the LAST n, not the first.",
            "argv": ["cage", "har", RICH, "-n", "1"],
        },
        {
            "name": "max-entries-zero-unlimited",
            "why": "0 is the documented 'unlimited', not 'none'.",
            "argv": ["cage", "har", RICH, "-n", "0"],
        },
        # ── the output file ──
        {
            "name": "output-file",
            "why": "A trailing newline on the file, and a count on stderr.",
            "argv": ["cage", "har", RICH, "-o", "{HOME}/export.har"],
            "capture_file": "export.har",
        },
        {
            "name": "output-file-json-lines",
            "why": "The JSONL branch writes no count. An inconsistency, recorded.",
            "argv": ["cage", "har", RICH, "--json-lines", "-o", "{HOME}/export.jsonl"],
            "capture_file": "export.jsonl",
        },
        # ── what a real capture directory does to a reader ──
        {
            "name": "rotated-generation-first",
            "why": "capture.jsonl.1 holds the older half and is read before the live file.",
            "argv": ["cage", "har", RICH, "--json-lines"],
            "setup": [_write(RICH_CAPTURE + ".1", ROTATED_LINE)],
        },
        {
            "name": "truncated-tail-dropped",
            "why": "A writer killed mid-line loses that line and nothing else.",
            "argv": ["cage", "har", RICH, "--json-lines"],
            "setup": [_append(RICH_CAPTURE, TRUNCATED_TAIL)],
        },
        {
            "name": "unparseable-lines-skipped",
            "why": "Non-JSON noise in the capture file is dropped, not fatal.",
            "argv": ["cage", "har", RICH, "--json-lines"],
            "setup": [_write(RICH_CAPTURE, "not json\n\n   \n[1,2,3]\n")],
        },
        # ── the corpus capture, through the command ──
        #
        # `golden_har.rs` already proves the builder against these five
        # artifacts. What these two add is the *command's* serialization
        # over the same input: the corpus stores
        # `sort_keys=True, ensure_ascii=False` and `cage har` writes
        # `json.dumps(har, indent=2)`, so the bytes differ from the
        # corpus's by design and have to be pinned separately.
        {
            "name": "corpus-capture-inbound",
            "why": "The golden corpus's own capture.jsonl, in the shipped serialization.",
            "argv": ["cage", "har", RICH],
            "setup": [_copy(CORPUS_CAPTURE, RICH_CAPTURE)],
        },
        {
            "name": "corpus-capture-outbound",
            "why": "The same, in the view that carries real secrets.",
            "argv": ["cage", "har", RICH, "--view", "outbound"],
            "setup": [_copy(CORPUS_CAPTURE, RICH_CAPTURE)],
        },
        # ── the error paths ──
        {
            "name": "missing-cage",
            "why": "No stored cage.yaml.",
            "argv": ["cage", "har", "no-such-cage"],
            "exit": 1,
        },
        {
            "name": "capture-disabled",
            "why": (
                "`capture: enable_har: false` and 'the file is not there yet' "
                "are the same error — there is no state that distinguishes them."
            ),
            "argv": ["cage", "har", MINIMAL],
            "exit": 1,
        },
        {
            "name": "legacy-v021-cage",
            "why": "The v0.22 gate, which exits 2 rather than 1.",
            "argv": ["cage", "har", MINIMAL],
            "setup": [_legacy_metadata("0.21.3")],
            "exit": 2,
        },
        {
            "name": "no-metadata-reads-as-legacy",
            "why": "A missing metadata.json defaults to v0.0.0 and trips the same gate.",
            "argv": ["cage", "har", MINIMAL],
            "setup": [_remove(MINIMAL_METADATA)],
            "exit": 2,
        },
    ]


def _build_home(root: Path) -> Path:
    """A7's snapshot, copied into a home with both XDG trees under it."""
    home = root / "home"
    shutil.copytree(_STATE_FIXTURE / "xdg-config", home / ".config")
    shutil.copytree(_STATE_FIXTURE / "xdg-data", home / ".local" / "share")
    return home


def _apply(home: Path, setup: list[dict]) -> None:
    for op in setup:
        target = home / op["path"]
        if op["op"] == "remove":
            target.unlink()
        elif op["op"] == "write":
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(op["text"])
        elif op["op"] == "copy":
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(_ROOT / op["from"], target)
        elif op["op"] == "append":
            with open(target, "a") as handle:
                handle.write(op["text"])
        else:  # pragma: no cover - a typo in this file, not a fixture state
            raise SystemExit(f"unknown setup op {op['op']!r}")


def _run_case(case: dict, version: str) -> dict:
    """Run one case in its own sandbox and record everything it produced."""
    with tempfile.TemporaryDirectory(prefix="agentcage-har-fixture-") as tmp:
        home = _build_home(Path(tmp))
        _apply(home, case.get("setup", []))

        argv = [arg.replace("{HOME}", str(home)) for arg in case["argv"]]
        env = dict(os.environ)
        env["HOME"] = str(home)
        env["XDG_CONFIG_HOME"] = str(home / ".config")
        env["XDG_DATA_HOME"] = str(home / ".local" / "share")
        # click styles nothing into a pipe, but be explicit: the bytes
        # recorded here are compared against a Rust process that has
        # made the same promise.
        env["NO_COLOR"] = "1"
        env.pop("AGENTCAGE_FORCE_COLOR", None)

        completed = subprocess.run(
            [sys.executable, "-c", "from agentcage.cli import main; main()", *argv],
            env=env,
            capture_output=True,
            text=True,
            cwd=tmp,
        )

        def scrub(text: str) -> str:
            text = text.replace(str(home), "{HOME}")
            return text.replace(f'"version": "{version}"', '"version": "{VERSION}"')

        recorded = {
            "name": case["name"],
            "why": case["why"],
            "argv": case["argv"],
            "setup": case.get("setup", []),
            "exit_code": completed.returncode,
            "stdout": scrub(completed.stdout),
            "stderr": scrub(completed.stderr),
        }
        if "capture_file" in case:
            written = home / case["capture_file"]
            recorded["output_path"] = case["capture_file"]
            recorded["output_text"] = scrub(written.read_text())

        expected = case.get("exit", 0)
        if completed.returncode != expected:
            raise SystemExit(
                f"case {case['name']}: expected exit {expected}, got "
                f"{completed.returncode}\n{completed.stderr}"
            )
        if "Traceback" in completed.stderr:
            raise SystemExit(
                f"case {case['name']}: the Python raised. A case that only "
                f"records a traceback pins a bug, not a contract.\n"
                f"{completed.stderr}"
            )
        return recorded


def generate() -> dict:
    from importlib.metadata import version as package_version

    version = package_version("agentcage")
    return {
        "generator": "scripts/gen-cage-har-fixture.py",
        "state_fixture": "tests/fixtures/state-compat/0.40.1",
        "version": version,
        "cases": [_run_case(case, version) for case in cases()],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the committed fixture is not what this run produces.",
    )
    args = parser.parse_args()

    produced = json.dumps(generate(), indent=2, sort_keys=False) + "\n"
    target = _OUT / "cases.json"

    if args.check:
        if not target.is_file():
            print(f"{target} does not exist", file=sys.stderr)
            return 1
        current = target.read_text()
        if current != produced:
            print(f"{target} is stale — rerun without --check", file=sys.stderr)
            import difflib

            sys.stderr.writelines(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    produced.splitlines(keepends=True),
                    fromfile="committed",
                    tofile="generated",
                )
            )
            return 1
        print(f"{target} is current ({len(cases())} cases)")
        return 0

    _OUT.mkdir(parents=True, exist_ok=True)
    target.write_text(produced)
    print(f"wrote {target} ({len(cases())} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
