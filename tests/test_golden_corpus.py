"""Check that the live code still reproduces the committed golden corpus.

The corpus under ``tests/fixtures/golden/`` is a characterization net over
everything the host derives from a ``cage.yaml``: quadlets, ``proxy-config
.yaml``, ``dns-allowlist.conf``, ``placeholders.env``, the fingerprint, HAR
and audit output, volume-mount parsing, and every validation error and
warning string.  If a change here fails, either the change altered
operator-visible behaviour (and the corpus must be re-blessed *deliberately*,
with the diff reviewed) or it is a regression.

Regenerate with::

    uv run python scripts/gen-golden-corpus.py

The harness is run in a **subprocess**.  It has to pin ``platform.system``,
``importlib.metadata.version``, ``secrets.token_hex`` and the XDG environment
process-wide to be deterministic, and doing that inside the pytest process
would poison every other test module.
"""

from __future__ import annotations

import difflib
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDEN_DIR = REPO_ROOT / "tests" / "fixtures" / "golden"
HARNESS = REPO_ROOT / "scripts" / "gen-golden-corpus.py"

# Inputs, not outputs: the harness reads these and never rewrites them.
_INPUT_PREFIXES = ("_inputs/",)

_MAX_REPORTED_DIFFS = 8
_MAX_DIFF_LINES = 40


# ---------------------------------------------------------------------------
# Comparison policy — see RUST-PORT-PLAN.md §2.8
# ---------------------------------------------------------------------------
#
# Two comparison modes, and the split is deliberate. Do not "fix" it by making
# everything byte-exact.
#
#   * YAML artifacts are compared **by parsed value**. PyYAML's emitter is not
#     reproducible from another language: it wraps at 80 columns, does not
#     indent sequences under a mapping key, and applies its own quoting
#     heuristics. Demanding byte equality for YAML would force the Rust port
#     to reimplement PyYAML's line-breaking algorithm, which is not a property
#     anything actually depends on — the egress parses these files, it does
#     not diff them. What must survive the port is the *value*.
#
#   * Everything else is compared **byte-for-byte**: quadlet units, env files,
#     dnsmasq config, hashes, JSON, and error/warning strings. These either
#     feed a byte-sensitive consumer (systemd, dnsmasq, sha256) or are UX that
#     users read and tests assert verbatim.
#
# The fingerprint is safe on either side of this line: fingerprint.py hashes
# the *parsed* cage.yaml, not its text.

def _is_yaml(rel: str) -> bool:
    return rel.endswith((".yaml", ".yml"))


def _compare(rel: str, expected: str, actual: str) -> str | None:
    """Return a human-readable difference, or None when the two agree."""
    if _is_yaml(rel):
        try:
            want = yaml.safe_load(expected)
            got = yaml.safe_load(actual)
        except yaml.YAMLError:
            # Some corpus INPUTS are deliberately malformed YAML (they exist
            # to pin the parser's error message). Unparseable text has no
            # value to compare, so fall back to bytes.
            return None if expected == actual else (
                f"{rel}: bytes differ (unparseable YAML, compared "
                f"byte-for-byte)\n" + _unified(rel, expected, actual))
        if want == got:
            return None
        return (
            f"{rel}: YAML values differ (compared semantically, not "
            f"byte-for-byte — see the comment in this test file)\n"
            + _unified(rel, yaml.safe_dump(want, sort_keys=True),
                       yaml.safe_dump(got, sort_keys=True))
        )
    if expected == actual:
        return None
    return f"{rel}: bytes differ\n" + _unified(rel, expected, actual)


def _unified(rel: str, expected: str, actual: str) -> str:
    lines = list(difflib.unified_diff(
        expected.splitlines(keepends=True),
        actual.splitlines(keepends=True),
        fromfile=f"golden/{rel}",
        tofile=f"regenerated/{rel}",
        n=2,
    ))
    if len(lines) > _MAX_DIFF_LINES:
        lines = lines[:_MAX_DIFF_LINES] + [
            f"... ({len(lines) - _MAX_DIFF_LINES} more diff lines)\n"]
    return "".join(lines)


# ---------------------------------------------------------------------------
# Regeneration
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def regenerated(tmp_path_factory) -> Path:
    """Run the harness into a throwaway directory and return it."""
    out = tmp_path_factory.mktemp("golden-regen") / "corpus"
    # A clean environment: the harness pins HOME/XDG itself, but an inherited
    # XDG_* from the developer's shell must not reach the child before it does.
    env = {
        k: v for k, v in os.environ.items()
        if not k.startswith(("XDG_", "AGENTCAGE_"))
    }
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, str(HARNESS), "--out", str(out)],
        capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
    )
    if proc.returncode != 0:
        pytest.fail(
            "golden-corpus harness failed:\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return out


def _tree(root: Path) -> dict[str, Path]:
    return {
        str(p.relative_to(root)): p
        for p in sorted(root.rglob("*")) if p.is_file()
        and not str(p.relative_to(root)).startswith(_INPUT_PREFIXES)
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_corpus_is_committed():
    assert GOLDEN_DIR.is_dir(), (
        f"{GOLDEN_DIR} is missing — run "
        "`uv run python scripts/gen-golden-corpus.py`"
    )
    assert (GOLDEN_DIR / "manifest.json").is_file()
    assert (GOLDEN_DIR / "README.md").is_file()


def test_live_code_reproduces_the_corpus(regenerated):
    golden = _tree(GOLDEN_DIR)
    fresh = _tree(regenerated)

    # README.md is hand-written, not generated.
    golden.pop("README.md", None)

    missing = sorted(set(golden) - set(fresh))
    extra = sorted(set(fresh) - set(golden))

    problems: list[str] = []
    if missing:
        problems.append(
            "artifacts the live code no longer produces (%d):\n  %s"
            % (len(missing), "\n  ".join(missing[:_MAX_REPORTED_DIFFS])))
    if extra:
        problems.append(
            "artifacts the live code now produces that are not committed "
            "(%d):\n  %s"
            % (len(extra), "\n  ".join(extra[:_MAX_REPORTED_DIFFS])))

    changed: list[str] = []
    for rel in sorted(set(golden) & set(fresh)):
        diff = _compare(
            rel,
            golden[rel].read_text(encoding="utf-8"),
            fresh[rel].read_text(encoding="utf-8"),
        )
        if diff is not None:
            changed.append(diff)

    if changed:
        head = changed[:_MAX_REPORTED_DIFFS]
        problems.append(
            "%d artifact(s) changed:\n\n%s%s" % (
                len(changed), "\n".join(head),
                "" if len(changed) <= _MAX_REPORTED_DIFFS else
                f"\n... and {len(changed) - _MAX_REPORTED_DIFFS} more",
            ))

    if problems:
        pytest.fail(
            "The golden corpus no longer matches the live code.\n\n"
            + "\n\n".join(problems)
            + "\n\nIf this change is intended, re-bless deliberately:\n"
              "    uv run python scripts/gen-golden-corpus.py\n"
              "and review the resulting diff — every line of it is behaviour "
              "a user or the Rust port can see.",
            pytrace=False,
        )


def test_every_reachable_config_raise_is_still_covered(regenerated):
    """The corpus must not quietly lose a validation error it once exercised.

    Keys are ``<qualname>#<n>`` (the n-th ``raise`` in that function), so this
    survives unrelated edits to ``config.py`` and fires only when a raise site
    that the corpus used to reach stops being reached — which means either the
    error became unreachable or the case that reached it was dropped.
    """
    import json

    committed = json.loads(
        (GOLDEN_DIR / "raise-coverage.json").read_text())
    fresh = json.loads((regenerated / "raise-coverage.json").read_text())

    lost = sorted(set(committed["covered"]) - set(fresh["covered"]))
    assert not lost, (
        "these config.py raise sites were covered by the corpus and no "
        "longer are:\n  " + "\n  ".join(lost)
        + "\n\nAdd a case to scripts/gen-golden-corpus.py:_invalid_cases(), "
          "or — if the error is genuinely gone — regenerate the corpus."
    )


def test_corpus_size_is_sane():
    """A corpus nobody can review is a corpus nobody reviews."""
    total = sum(p.stat().st_size for p in GOLDEN_DIR.rglob("*") if p.is_file())
    assert total < 20 * 1024 * 1024, (
        f"golden corpus is {total / 1048576:.1f} MiB; trim it before it stops "
        "being reviewable (see README.md)"
    )
