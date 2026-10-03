#!/usr/bin/env python3
"""Enforce the invariants that keep Python out of the shipped product.

After the Rust port the host CLI is a binary and the *only* Python that
ships is the egress proxy, inside the mitmproxy image. Three things
would quietly undo that, and none of them would fail any other check in
this repository:

1. **The Rust binary shelling out to ``python``.** Then the binary is
   not self-contained, and an install with no interpreter breaks at
   whichever subcommand happens to reach that line.
2. **The proxy importing a package the egress image does not install.**
   ``Containerfile.egress`` pip-installs exactly ``pyyaml`` and
   ``cryptography`` on top of the mitmproxy base. An import of anything
   else is an ``ImportError`` inside the cage at runtime, which is the
   worst place to find out.
3. **A shipped Containerfile installing Python.** ``Containerfile.egress``
   is the one image that is allowed to have an interpreter. Scaffold
   Containerfiles are exempt — they build the *workload*, which is
   whatever the operator wants.

RUST-PORT-PLAN.md §2.4. Each check reports independently, so a run says
everything that is wrong rather than only the first thing.

Exit status is 0 when every invariant holds, 1 otherwise.
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── 1. no Python from Rust ───────────────────────────────────

#: Rust files allowed to name a Python interpreter, and why.
#:
#: The single exception the plan grants. `cage verify` runs a probe
#: INSIDE the cage, where the workload image's interpreter is the
#: subject of the test rather than a dependency of the host binary —
#: the host never executes it.
RUST_PYTHON_ALLOWED = {
    "rust/agentcage-cli/src/cli/cage/verify.rs": (
        "the in-cage probe: this python3 runs in the workload container, "
        "not on the host"
    ),
}

#: `"python"` / `"python3"` as a whole string literal.
_RUST_PYTHON = re.compile(r'"python3?"')


def _rust_sources() -> list[Path]:
    """Every `.rs` file that becomes the binary.

    `rust/*/src/**` only — deliberately **not** `tests/`. The invariant
    is about what the shipped binary needs at runtime, and the test
    suite invoking an interpreter is not a violation of it but the
    opposite: `fingerprint_python_crossing` and `yaml_pyyaml_crossing`
    exist precisely to run the same input through CPython and compare,
    which is what makes the port's oracles trustworthy. A guard that
    forbade those would be arguing against its own evidence.
    """
    return sorted(
        path
        for crate in sorted((ROOT / "rust").iterdir())
        if crate.is_dir()
        for path in (crate / "src").rglob("*.rs")
    )


def check_rust_has_no_python() -> list[str]:
    problems: list[str] = []
    seen_allowed: set[str] = set()
    for path in _rust_sources():
        rel = path.relative_to(ROOT).as_posix()
        for number, line in enumerate(path.read_text().splitlines(), 1):
            # A doc comment or a `//` comment may discuss python freely;
            # what matters is an argv.
            stripped = line.lstrip()
            if stripped.startswith("//"):
                continue
            if not _RUST_PYTHON.search(line):
                continue
            if rel in RUST_PYTHON_ALLOWED:
                seen_allowed.add(rel)
                continue
            problems.append(
                f"{rel}:{number}: Rust must not shell out to a Python "
                f"interpreter — the binary has to stand alone\n"
                f"    {stripped}"
            )
    # An allowlist entry that no longer matches anything is a stale
    # exemption, and a stale exemption is how the next one gets waved
    # through. Fail on it.
    for rel, why in RUST_PYTHON_ALLOWED.items():
        if rel not in seen_allowed:
            problems.append(
                f"{rel}: allowlisted for '{why}' but names no interpreter "
                f"any more — drop the entry from RUST_PYTHON_ALLOWED"
            )
    return problems


# ── 2. the proxy's imports ───────────────────────────────────

PROXY = ROOT / "src" / "agentcage" / "data" / "proxy"

#: What `Containerfile.egress` puts on top of the mitmproxy base.
#:
#: `mitmproxy` itself comes with the base image; `pyyaml` and
#: `cryptography` are the pip install. Nothing else is there, so nothing
#: else may be imported.
EGRESS_THIRD_PARTY = {"mitmproxy", "yaml", "cryptography"}


def _proxy_local_names() -> set[str]:
    """Modules the proxy can import as bare names.

    `pyproject.toml` puts `src/agentcage/data/proxy` on the pythonpath,
    and the egress image copies the same tree to a directory on
    `sys.path`, so `import policy_api` resolves in both. Derived from
    the directory rather than listed, so a new module needs no edit
    here.
    """
    names = {"agentcage"}
    for entry in PROXY.iterdir():
        if entry.is_dir() and (entry / "__init__.py").exists():
            names.add(entry.name)
        elif entry.suffix == ".py":
            names.add(entry.stem)
    return names


def check_proxy_imports_only_what_the_image_has() -> list[str]:
    allowed = (
        set(sys.stdlib_module_names) | EGRESS_THIRD_PARTY | _proxy_local_names()
    )
    problems: list[str] = []
    for path in sorted(PROXY.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        tree = ast.parse(path.read_text(), filename=str(path))
        # `walk`, not a top-level scan: `google_jwt_bearer` imports
        # cryptography inside a function precisely so the module loads
        # without it, and a function-level import of something absent
        # fails just as hard when the branch is taken.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [(alias.name.split(".")[0], node.lineno) for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # A relative import resolves inside this tree.
                if node.level:
                    continue
                roots = [((node.module or "").split(".")[0], node.lineno)]
            else:
                continue
            for root, lineno in roots:
                if root and root not in allowed:
                    problems.append(
                        f"{rel}:{lineno}: the egress image installs only "
                        f"{', '.join(sorted(EGRESS_THIRD_PARTY))} — "
                        f"'{root}' would be an ImportError inside the cage"
                    )
    return problems


# ── 3. no interpreter in a shipped image ─────────────────────

CONTAINERS = ROOT / "src" / "agentcage" / "data" / "containers"

#: The one image allowed an interpreter: it *is* the Python.
CONTAINERFILE_WITH_PYTHON = "Containerfile.egress"

#: Package names that mean "this image has an interpreter".
_INSTALLS_PYTHON = re.compile(
    r"\b(python3?(-minimal|-full)?|py3-\w+|python3?-pip)\b"
)


def check_shipped_images_have_no_python() -> list[str]:
    problems: list[str] = []
    for path in sorted(CONTAINERS.glob("Containerfile*")):
        if path.name == CONTAINERFILE_WITH_PYTHON:
            continue
        rel = path.relative_to(ROOT).as_posix()
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if not line.lstrip().upper().startswith(("RUN", "FROM")) and (
                "install" not in line
            ):
                continue
            if line.lstrip().startswith("#"):
                continue
            if _INSTALLS_PYTHON.search(line):
                problems.append(
                    f"{rel}:{number}: only {CONTAINERFILE_WITH_PYTHON} may "
                    f"ship an interpreter\n    {line.strip()}"
                )
    return problems


# ── driver ───────────────────────────────────────────────────

CHECKS = (
    ("Rust does not shell out to Python", check_rust_has_no_python),
    ("the proxy imports only what the egress image installs",
     check_proxy_imports_only_what_the_image_has),
    ("no shipped Containerfile but the egress installs Python",
     check_shipped_images_have_no_python),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="list what each check looked at",
    )
    args = parser.parse_args()

    failed = 0
    for title, check in CHECKS:
        problems = check()
        status = "ok   " if not problems else "FAIL "
        print(f"{status} {title}", flush=True)
        for problem in problems:
            print(f"        {problem}", flush=True)
        failed += len(problems)

    if failed:
        print(
            f"\n{failed} invariant violation(s). These keep Python out of "
            f"the shipped product — see RUST-PORT-PLAN.md §2.4.",
            file=sys.stderr,
        )
        return 1
    if args.verbose:
        print(
            f"\nscanned {len(_rust_sources())} Rust source files, "
            f"{len(list(PROXY.rglob('*.py')))} proxy modules, "
            f"{len(list(CONTAINERS.glob('Containerfile*')))} Containerfiles"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
