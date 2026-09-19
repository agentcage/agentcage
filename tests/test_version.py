"""The version is written down once, in the root VERSION file.

`scripts/check-version.sh` enforces agreement between VERSION, pyproject
and the CHANGELOG without needing anything installed. This module covers
the one thing a shell script cannot see: that the *installed* package
actually reports what VERSION says.

That matters because ~10 call sites across the CLI read
``importlib.metadata.version("agentcage")`` and stamp the answer into the
egress image tag, the quadlet ``Image=`` pin and ``proxy-config.yaml``.
If hatchling's VERSION wiring breaks, those keep working against a stale
number instead of failing, so nothing else would notice.
"""

from __future__ import annotations

import re
import subprocess
from importlib.metadata import version as pkg_version
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = REPO_ROOT / "VERSION"


def read_version() -> str:
    return VERSION_FILE.read_text().strip()


def test_version_file_is_a_single_trimmed_line():
    raw = VERSION_FILE.read_text()
    assert raw.endswith("\n"), "VERSION must end with a newline"
    assert raw.count("\n") == 1, "VERSION must hold exactly one line"
    assert raw == raw.strip() + "\n", "VERSION must carry no padding"


def test_version_file_is_semver():
    assert re.fullmatch(
        r"\d+\.\d+\.\d+(?:[.-]?(?:a|b|rc|alpha|beta|dev)\d+)?", read_version()
    ), f"VERSION {read_version()!r} is not a semantic version"


def test_installed_metadata_matches_version_file():
    """The wheel hatchling built reports what VERSION says.

    A mismatch means the ``[tool.hatch.version]`` wiring silently fell
    back to something else, and every image tag the CLI stamps is wrong.
    """
    assert pkg_version("agentcage") == read_version()


def test_pyproject_declares_the_version_dynamic():
    """No second source of truth."""
    text = (REPO_ROOT / "pyproject.toml").read_text()
    project = text.split("[project]", 1)[1].split("\n[", 1)[0]
    assert 'dynamic = ["version"]' in project
    assert not re.search(r"^version\s*=", project, re.MULTILINE)


def test_changelog_documents_the_current_version():
    """publish.yml builds the release body from this heading.

    If it is absent the release ships with a "no CHANGELOG entry"
    placeholder instead of notes, which has happened before.
    """
    headings = re.findall(
        r"^## \[([^\]]+)\]", (REPO_ROOT / "CHANGELOG.md").read_text(), re.MULTILINE
    )
    released = [h for h in headings if h.lower() != "unreleased"]
    assert released, "CHANGELOG.md has no released version heading"
    assert released[0] == read_version()


@pytest.mark.skipif(
    not (REPO_ROOT / "scripts" / "check-version.sh").exists(),
    reason="check-version.sh not present",
)
def test_check_version_script_passes_on_the_tree_as_committed():
    proc = subprocess.run(
        [str(REPO_ROOT / "scripts" / "check-version.sh")],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr


def test_check_version_script_rejects_a_mismatched_tag():
    """The guard that keeps `git tag v0.41.0` off a 0.40.1 tree."""
    proc = subprocess.run(
        [str(REPO_ROOT / "scripts" / "check-version.sh"), "v99.99.99"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "does not match VERSION" in proc.stderr
