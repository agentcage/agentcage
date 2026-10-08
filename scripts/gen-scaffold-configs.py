#!/usr/bin/env python3
"""Render every built-in scaffold's ``cage.yaml.j2`` and parse the result.

The golden corpus (``tests/fixtures/golden/``) is a matrix of configs
written *for* it. The scaffolds are the configs agentcage actually hands
a new user, and `agentcage init --scaffold claude-code` is by far the
most common way a cage.yaml comes into existence — so the Rust port's
parser has to read them, and read them the same way Python does.

This writes, per scaffold:

    tests/fixtures/scaffold-configs/<name>/cage.yaml        the render
    tests/fixtures/scaffold-configs/<name>/resolved-config.json
                                                            load_config's result

``resolved-config.json`` is byte-identical in form to the corpus's, from
the same ``_dataclass_to_jsonable`` + ``json.dumps(indent=2,
sort_keys=True, ensure_ascii=False)`` pair, so ``rust/agentcage-core/
tests/golden_config.rs`` compares both trees with one code path.

Determinism, for the same reasons ``gen-golden-corpus.py`` pins things:
``config._host_dns_servers()`` reads the host's ``/etc/resolv.conf`` and
``platform.system()`` decides the default isolation backend. Both are
pinned here to the values the corpus uses, so this script produces the
same bytes on a laptop and in CI.

Usage:

    uv run python scripts/gen-scaffold-configs.py [--check]

``--check`` regenerates into a temporary directory and diffs, which is
what a pre-commit or CI step wants.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import platform
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "tests" / "fixtures" / "scaffold-configs"

# The same frozen values gen-golden-corpus.py uses, so a reader
# comparing the two trees is not distracted by a different resolver.
FROZEN_DNS_SERVERS = ["192.0.2.53", "192.0.2.54"]

# The scaffold cage.yaml templates take a cage name; a fixed one keeps
# the rendered network addresses stable.
CAGE_NAME = "demo"


_PLACEHOLDER_COUNTER = {"n": 0}


def _pin() -> None:
    """Freeze everything the render and the parse read from the host."""
    sys.path.insert(0, str(REPO / "src"))
    import secrets as _secrets

    from agentcage import config

    config._host_dns_servers = lambda: list(FROZEN_DNS_SERVERS)
    platform.system = lambda: "Linux"
    platform.machine = lambda: "x86_64"

    # `init.py` exposes a `placeholder()` Jinja global, and several
    # scaffolds call it -- so a rendered cage.yaml carries 128 bits of
    # fresh entropy per secret_injection rule. Same counter trick
    # gen-golden-corpus.py uses, restarted per scaffold so adding one
    # does not renumber the others.
    def _token_hex(n: int = 16) -> str:
        _PLACEHOLDER_COUNTER["n"] += 1
        return "%0*x" % (n * 2, _PLACEHOLDER_COUNTER["n"])

    _secrets.token_hex = _token_hex


def _jsonable(value):
    """``gen-golden-corpus.py``'s ``_dataclass_to_jsonable``, verbatim."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name))
                for f in dataclasses.fields(value)}
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_jsonable(v) for v in value)
    return value


def _scaffolds() -> list[str]:
    """Every built-in scaffold directory holding a ``cage.yaml.j2``."""
    root = REPO / "src" / "agentcage" / "scaffolds"
    return sorted(
        d.name for d in root.iterdir()
        if d.is_dir() and (d / "cage.yaml.j2").exists()
    )


def generate(out: Path) -> list[str]:
    from agentcage import init
    from agentcage.config import load_config

    names = _scaffolds()
    if not names:
        raise SystemExit("no scaffolds with a cage.yaml.j2 found")

    with tempfile.TemporaryDirectory() as staging:
        for name in names:
            _PLACEHOLDER_COUNTER["n"] = 0
            rendered = init.render_config(CAGE_NAME, scaffold=name)
            source = Path(staging) / f"{name}.yaml"
            source.write_text(rendered, encoding="utf-8")
            cfg = load_config(str(source))

            case = out / name
            case.mkdir(parents=True, exist_ok=True)
            (case / "cage.yaml").write_text(rendered, encoding="utf-8")
            (case / "resolved-config.json").write_text(
                json.dumps(_jsonable(cfg), indent=2, sort_keys=True,
                           ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    (out / "MANIFEST.txt").write_text(
        "".join(f"{name}\n" for name in names), encoding="utf-8"
    )
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="regenerate elsewhere and diff instead of writing")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    _pin()

    if args.check:
        with tempfile.TemporaryDirectory() as tmp:
            fresh = Path(tmp) / "scaffold-configs"
            generate(fresh)
            stale = []
            for path in sorted(fresh.rglob("*")):
                if path.is_dir():
                    continue
                rel = path.relative_to(fresh)
                committed = OUT / rel
                if not committed.exists():
                    stale.append(f"missing: {rel}")
                elif committed.read_bytes() != path.read_bytes():
                    stale.append(f"differs: {rel}")
            for path in sorted(OUT.rglob("*")):
                if path.is_file() and not (fresh / path.relative_to(OUT)).exists():
                    stale.append(f"extra:   {path.relative_to(OUT)}")
            if stale:
                print("\n".join(stale))
                print("\nRe-run: uv run python scripts/gen-scaffold-configs.py")
                return 1
        print("scaffold configs are up to date")
        return 0

    names = generate(args.out or OUT)
    print(f"wrote {len(names)} scaffold configs: {', '.join(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
