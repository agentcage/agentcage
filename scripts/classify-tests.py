#!/usr/bin/env python3
"""Classify every file in ``tests/`` by which side of the trust boundary it imports.

agentcage is being split by language at its trust boundary (see
``RUST-PORT-PLAN.md`` §2.4):

* **host** — ``src/agentcage/**`` except ``data/proxy/``. Becomes Rust. Its
  tests are deleted and replaced by Rust tests.
* **proxy** — ``src/agentcage/data/proxy/**``. Stays Python forever, inside the
  egress container. Its tests stay as pytest.

A test file that imports *both* sides has no home after the split: it cannot be
deleted with the host tests (it would take proxy coverage with it) and it cannot
stay as pytest (it would import a module that no longer exists in Python). Such
files must be split *now*, while both implementations are still Python and the
separation is mechanically verifiable.

This script is the seed of the §2.4 CI invariant guards. Run with
``--fail-on-both`` (as CI does) to enforce that the count of boundary-straddling
test files stays at zero.

Proxy modules are importable two ways, because ``pyproject.toml`` sets
``pythonpath = ["src", "src/agentcage/data/proxy"]``:

    from agentcage.data.proxy.addon import Agentcage   # qualified
    import addon                                       # bare

Both spellings are recognised, as are late (function-body) imports,
``importlib.import_module`` / ``importlib.reload``, ``__import__``, and dotted
target strings handed to ``monkeypatch.setattr`` / ``mock.patch``.

Usage::

    python3 scripts/classify-tests.py                 # human summary
    python3 scripts/classify-tests.py --json out.json  # machine-readable report
    python3 scripts/classify-tests.py --fail-on-both   # CI guard
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
HOST_PKG = SRC / "agentcage"
PROXY_DIR = HOST_PKG / "data" / "proxy"
TESTS_DIR = REPO_ROOT / "tests"

HOST = "host"
PROXY = "proxy"
BOTH = "both"
NEUTRAL = "neutral"
CROSS = "cross-language"

# Files that legitimately touch both sides and are not test modules. Only
# pytest collection infrastructure belongs here; it must never be used to
# exempt an actual test file from the boundary rule.
EXEMPT = {
    "conftest.py",
}

# The one place a straddling assertion may live: a test whose entire purpose is
# to assert that a host implementation and a proxy implementation AGREE (see
# RUST-PORT-PLAN.md §2.2). Such an assertion belongs to neither side by
# construction. PR A4 replaces this directory with language-neutral JSON
# fixtures asserted independently by the Rust suite and by pytest, after which
# it goes away. It is reported separately and loudly so it cannot quietly
# become a dumping ground for un-split test files.
CROSS_LANGUAGE_DIR = "tests/cross_language"


# ── module inventory ──────────────────────────────────────────────


def proxy_top_level_names() -> set[str]:
    """Top-level names importable *bare* because ``src/agentcage/data/proxy``
    is on ``pythonpath`` (e.g. ``addon``, ``inspectors``, ``relays``)."""
    names: set[str] = set()
    if not PROXY_DIR.is_dir():
        return names
    for entry in PROXY_DIR.iterdir():
        if entry.name.startswith((".", "_")) and entry.name != "__init__.py":
            continue
        if entry.is_dir() and (entry / "__init__.py").exists():
            names.add(entry.name)
        elif entry.suffix == ".py" and entry.stem != "__init__":
            names.add(entry.stem)
    return names


def host_top_level_names() -> set[str]:
    """Names under ``src/agentcage/`` that are host-side, for recognising
    dotted patch-target strings like ``"agentcage.config._host_dns_servers"``.
    (Host code is only ever importable as ``agentcage.X``; ``src`` is on the
    path, not ``src/agentcage``.)"""
    names: set[str] = set()
    if not HOST_PKG.is_dir():
        return names
    for entry in HOST_PKG.iterdir():
        if entry.name in {"__pycache__", "py.typed"}:
            continue
        if entry.is_dir() and (entry / "__init__.py").exists():
            names.add(entry.name)
        elif entry.suffix == ".py" and entry.stem != "__init__":
            names.add(entry.stem)
    return names


PROXY_NAMES = proxy_top_level_names()
HOST_NAMES = host_top_level_names()

PROXY_QUALIFIED = "agentcage.data.proxy"


def side_of(module: str | None) -> str | None:
    """Which side of the boundary a dotted module path belongs to.

    Returns ``"host"``, ``"proxy"``, or ``None`` for stdlib / third-party /
    test-support modules.
    """
    if not module:
        return None
    if module == PROXY_QUALIFIED or module.startswith(PROXY_QUALIFIED + "."):
        return PROXY
    if module == "agentcage" or module.startswith("agentcage."):
        return HOST
    head = module.split(".", 1)[0]
    if head in PROXY_NAMES:
        return PROXY
    return None


def side_of_attr_path(dotted: str) -> str | None:
    """Same as :func:`side_of`, but for an attribute path such as
    ``agentcage.config._host_dns_servers`` or ``policy_api._version`` — the
    strings handed to ``monkeypatch.setattr`` and ``mock.patch``. Requires at
    least one dot so bare words are not mistaken for modules."""
    if "." not in dotted:
        return None
    head = dotted.split(".", 1)[0]
    if head == "agentcage" or head in PROXY_NAMES or head in HOST_NAMES:
        return side_of(dotted)
    return None


# ── AST scanning ──────────────────────────────────────────────────


def _dotted(node: ast.AST) -> str | None:
    """Render an ``a.b.c`` Attribute/Name chain back to a dotted string."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


class Scanner(ast.NodeVisitor):
    """Collect every module reference in a file, however it is spelled."""

    def __init__(self) -> None:
        # side -> {module: [evidence strings]}
        self.refs: dict[str, dict[str, list[str]]] = {HOST: {}, PROXY: {}}
        self.notes: list[str] = []
        # Names bound to modules, so ``importlib.reload(secret_injector)``
        # can be resolved back to the module it reloads.
        self.aliases: dict[str, str] = {}

    def record(self, module: str | None, evidence: str, lineno: int) -> None:
        side = side_of(module)
        if side is None or module is None:
            return
        self.refs[side].setdefault(module, []).append(f"L{lineno}: {evidence}")

    # imports ------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.record(alias.name, f"import {alias.name}", node.lineno)
            bound = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[bound] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:  # relative import: never crosses into src/
            self.generic_visit(node)
            return
        names = ", ".join(a.name for a in node.names)
        self.record(node.module, f"from {node.module} import {names}", node.lineno)
        # ``from agentcage.data.proxy import addon`` also names a submodule.
        if node.module and side_of(node.module) is not None:
            for alias in node.names:
                sub = f"{node.module}.{alias.name}"
                self.aliases[alias.asname or alias.name] = sub
        self.generic_visit(node)

    # dynamic imports and patch targets ----------------------------

    def visit_Call(self, node: ast.Call) -> None:
        func = _dotted(node.func) or ""
        tail = func.rsplit(".", 1)[-1]

        # importlib.import_module("X") / __import__("X")
        if tail in {"import_module", "__import__"} and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self.record(arg.value, f"{func}({arg.value!r})", node.lineno)

        # importlib.reload(mod) — resolve mod through the alias table
        elif tail == "reload" and node.args:
            target = _dotted(node.args[0])
            if target:
                resolved = self.aliases.get(target.split(".", 1)[0], target)
                self.record(resolved, f"{func}({target})", node.lineno)

        # monkeypatch.setattr("agentcage.config.X", ...) / mock.patch("...")
        elif tail in {"setattr", "delattr", "patch", "patch.object", "object"} or func.endswith(
            ("monkeypatch.setattr", "mock.patch")
        ):
            for arg in node.args[:1]:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    side = side_of_attr_path(arg.value)
                    if side is not None:
                        module = arg.value.rsplit(".", 1)[0]
                        self.refs[side].setdefault(module, []).append(
                            f"L{node.lineno}: {tail}({arg.value!r})"
                        )

        # sys.path.insert(...) — the bare-name proxy convention. Not itself a
        # reference, but worth surfacing so a human reading the report knows
        # why bare ``import addon`` works in this file.
        elif func in {"sys.path.insert", "sys.path.append"}:
            self.notes.append(f"L{node.lineno}: {func}(...) — bare proxy imports possible")

        self.generic_visit(node)


def classify_file(path: Path) -> dict:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    scanner = Scanner()
    scanner.visit(tree)

    rel_path = path.relative_to(REPO_ROOT).as_posix()
    host_refs = scanner.refs[HOST]
    proxy_refs = scanner.refs[PROXY]
    if host_refs and proxy_refs:
        label = CROSS if rel_path.startswith(CROSS_LANGUAGE_DIR + "/") else BOTH
    elif host_refs:
        label = HOST
    elif proxy_refs:
        label = PROXY
    else:
        label = NEUTRAL

    return {
        "file": rel_path,
        "classification": label,
        "exempt": path.name in EXEMPT,
        "host_modules": sorted(host_refs),
        "proxy_modules": sorted(proxy_refs),
        "host_evidence": {m: ev for m, ev in sorted(host_refs.items())},
        "proxy_evidence": {m: ev for m, ev in sorted(proxy_refs.items())},
        "notes": scanner.notes,
    }


def scan(tests_dir: Path = TESTS_DIR) -> dict:
    results = [
        classify_file(p)
        for p in sorted(tests_dir.rglob("*.py"))
        if "__pycache__" not in p.parts
    ]
    counts = {HOST: 0, PROXY: 0, BOTH: 0, CROSS: 0, NEUTRAL: 0}
    for r in results:
        counts[r["classification"]] += 1
    violations = [
        r["file"] for r in results if r["classification"] == BOTH and not r["exempt"]
    ]
    return {
        "tests_dir": tests_dir.relative_to(REPO_ROOT).as_posix(),
        "total_files": len(results),
        "counts": counts,
        "violations": violations,
        "cross_language": [r["file"] for r in results if r["classification"] == CROSS],
        "proxy_top_level_names": sorted(PROXY_NAMES),
        "files": results,
    }


# ── reporting ─────────────────────────────────────────────────────

FAILURE_HELP = """\
A test file that imports BOTH the host side (src/agentcage/**, becoming Rust)
and the proxy side (src/agentcage/data/proxy/**, staying Python) has no home
after the language split: deleting it with the host tests would drop proxy
coverage, and keeping it as pytest would import a module that no longer exists
in Python.

To fix, split the file listed above into two:

  * tests/test_<name>.py        — host-side assertions only
  * tests/test_<name>_proxy.py  — proxy-side assertions only

If the test exists specifically to assert that a host function and a proxy
function AGREE (e.g. cli._is_never_grant vs policy_api._is_never_grant), that
assertion belongs on neither side. Move it to
tests/cross_language/ and leave a comment pointing at RUST-PORT-PLAN.md §2.2 —
PR A4 converts those into language-neutral JSON fixtures.

Preserve the test function names so failures stay greppable against history,
and do not drop any coverage: `uv run pytest --collect-only -q | tail -1` must
report the same number of tests before and after.

See RUST-PORT-PLAN.md §2.4 for the invariant this guard enforces."""


def human_summary(report: dict, verbose: bool = False) -> str:
    counts = report["counts"]
    lines = [
        f"Scanned {report['total_files']} files in {report['tests_dir']}/",
        "",
        f"  host    {counts[HOST]:>4}   imports src/agentcage/** only (becomes Rust tests)",
        f"  proxy   {counts[PROXY]:>4}   imports src/agentcage/data/proxy/** only (stays pytest)",
        f"  both    {counts[BOTH]:>4}   straddles the trust boundary (must be 0)",
        f"  cross   {counts[CROSS]:>4}   straddles on purpose, in {CROSS_LANGUAGE_DIR}/ (§2.2; A4 removes these)",
        f"  neutral {counts[NEUTRAL]:>4}   imports neither side",
        "",
    ]
    if report["cross_language"]:
        lines.append(f"cross-language conformance ({CROSS_LANGUAGE_DIR}/, temporary — see §2.2):")
        lines.extend(f"    {m}" for m in report["cross_language"])
        lines.append("")
    if verbose:
        for side in (HOST, PROXY, BOTH, CROSS, NEUTRAL):
            members = [r["file"] for r in report["files"] if r["classification"] == side]
            if members:
                lines.append(f"{side}:")
                lines.extend(f"    {m}" for m in members)
                lines.append("")
    if report["violations"]:
        lines.append("BOUNDARY VIOLATIONS:")
        for f in report["violations"]:
            entry = next(r for r in report["files"] if r["file"] == f)
            lines.append(f"  {f}")
            for mod, ev in entry["host_evidence"].items():
                lines.append(f"      host  {mod}  ({ev[0]})")
            for mod, ev in entry["proxy_evidence"].items():
                lines.append(f"      proxy {mod}  ({ev[0]})")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", metavar="PATH", help="write the JSON report to PATH ('-' for stdout)")
    ap.add_argument(
        "--fail-on-both",
        action="store_true",
        help="exit non-zero if any test file imports both sides of the boundary (CI guard)",
    )
    ap.add_argument("-v", "--verbose", action="store_true", help="list every file by class")
    ap.add_argument(
        "--tests-dir", default=str(TESTS_DIR), help="directory to scan (default: tests/)"
    )
    args = ap.parse_args(argv)

    report = scan(Path(args.tests_dir).resolve())

    if args.json == "-":
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.json != "-":
        print(human_summary(report, verbose=args.verbose))

    if args.fail_on_both and report["violations"]:
        n = len(report["violations"])
        print(
            f"ERROR: {n} test file(s) import both sides of the trust boundary "
            f"(expected 0).\n",
            file=sys.stderr,
        )
        for f in report["violations"]:
            print(f"  {f}", file=sys.stderr)
        print("\n" + FAILURE_HELP, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
