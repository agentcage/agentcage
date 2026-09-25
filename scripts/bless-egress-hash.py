#!/usr/bin/env python3
"""Regenerate tests/fixtures/egress_hash.json from the working tree.

    python3 scripts/bless-egress-hash.py          # rewrite the fixture
    python3 scripts/bless-egress-hash.py --check  # exit 1 if it is stale

**Re-blessing must be deliberate.** The fixture pins the digest that the
egress image tag is built from, and that digest is a cross-language
contract — the Rust port has to reproduce it byte-exactly (see
``src/agentcage/egress_hash.py``). A legitimate change to the egress build
inputs (editing the supervisor, adding a `COPY` to Containerfile.egress,
touching the addon tree) *should* move the hash, and running this script is
how you record that. A hash that moves for any other reason is a bug —
find out why before you bless it. The fixture also records the full sorted
``(relpath, size)`` input list precisely so the diff tells you *which*
files moved, not merely that the hash did.

Deliberately importable without installing agentcage: stdlib only, and the
only agentcage module it touches is the stdlib-only ``egress_hash``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from agentcage import egress_hash  # noqa: E402

FIXTURE = _REPO_ROOT / "tests" / "fixtures" / "egress_hash.json"


def build_fixture() -> dict:
    inputs = egress_hash.egress_build_inputs()
    return {
        "_comment": (
            "Pinned digest of the agentcage-egress image build inputs. "
            "Regenerate ONLY for a deliberate change to those inputs: "
            "python3 scripts/bless-egress-hash.py. See "
            "src/agentcage/egress_hash.py for the wire format, which the "
            "Rust port must reproduce byte-exactly."
        ),
        "algorithm": (
            "sha256 over sorted inputs, each contributing "
            "relpath(utf-8) || 0x00 || len(body) as 8-byte big-endian || "
            "body; hex digest truncated to the first 12 characters"
        ),
        "hash": egress_hash.egress_content_hash(),
        "input_count": len(inputs),
        # relpath -> size in bytes, in the hash's own sort order. One line
        # per file in the diff, so a change that adds or drops a COPY
        # source names the files instead of only moving the digest.
        "inputs": {rel: path.stat().st_size for rel, path in inputs},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 if the fixture is out of date",
    )
    args = ap.parse_args()

    fresh = build_fixture()
    text = json.dumps(fresh, indent=2) + "\n"

    if args.check:
        current = FIXTURE.read_text() if FIXTURE.is_file() else ""
        if current == text:
            print(f"egress hash fixture is current: {fresh['hash']}")
            return 0
        print(
            f"egress hash fixture is STALE (tree says {fresh['hash']}); "
            f"run scripts/bless-egress-hash.py if that is intended",
            file=sys.stderr,
        )
        return 1

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(text)
    print(f"wrote {FIXTURE.relative_to(_REPO_ROOT)}: "
          f"{fresh['hash']} over {fresh['input_count']} inputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
