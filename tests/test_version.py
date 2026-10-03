"""The version is written down once, in the root VERSION file.

`scripts/check-version.sh` enforces agreement between VERSION,
pyproject, the Cargo workspace and the CHANGELOG without needing
anything installed. This module covers the one thing a shell script
cannot see -- that the *installed* package actually reports what VERSION
says -- and pins the behaviour of the script's newer Cargo checks.

That matters because ~10 call sites across the CLI read
``importlib.metadata.version("agentcage")`` and stamp the answer into the
egress image tag, the quadlet ``Image=`` pin and ``proxy-config.yaml``.
If hatchling's VERSION wiring breaks, those keep working against a stale
number instead of failing, so nothing else would notice.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from importlib.metadata import version as pkg_version
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = REPO_ROOT / "VERSION"


CHECK_SCRIPT = REPO_ROOT / "scripts" / "check-version.sh"
CARGO_TOML = REPO_ROOT / "Cargo.toml"


def read_version() -> str:
    return VERSION_FILE.read_text().strip()


def rust_member_manifests() -> list[Path]:
    return sorted((REPO_ROOT / "rust").glob("*/Cargo.toml"))


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


# ── The Rust workspace ───────────────────────────────────────
#
# Cargo cannot read a version out of a file, so the root Cargo.toml
# keeps a copy of VERSION under [workspace.package] and every crate
# inherits it. These pin the guard that makes the copy safe; the guard
# itself lives in check-version.sh, because it has to keep working once
# there is no Python on the host to run pytest with (RUST-PORT-PLAN.md
# sections 2.3 and 2.4).


def test_cargo_workspace_version_matches_the_version_file():
    """`agentcage --version` will print this number once the CLI is Rust.

    It is also the egress image tag, the quadlet ``Image=`` pin and the
    ``proxy-config.yaml`` stamp, so drift here is not cosmetic -- it
    splits a deployment across two versions of the egress image.
    """
    workspace = tomllib.loads(CARGO_TOML.read_text())["workspace"]
    assert workspace["package"]["version"] == read_version()


def test_rust_crates_inherit_the_workspace_version():
    """No second source of truth, the same rule pyproject lives under.

    A member crate with its own ``version = "..."`` would win for that
    crate alone, so the binary could report one number while the image
    tag it stamps used another.
    """
    members = rust_member_manifests()
    assert members, "no crates under rust/*/Cargo.toml"

    for manifest in members:
        package = tomllib.loads(manifest.read_text())["package"]
        assert package.get("version") == {"workspace": True}, (
            f"{manifest.relative_to(REPO_ROOT)} must set version.workspace = true"
        )


def test_every_workspace_member_has_a_manifest():
    """The member list and the directory tree agree.

    Cargo errors on a member that does not exist, but says nothing about
    a crate directory nobody listed -- it just never gets built, tested
    or linted.
    """
    listed = set(tomllib.loads(CARGO_TOML.read_text())["workspace"]["members"])
    on_disk = {
        str(m.parent.relative_to(REPO_ROOT)) for m in rust_member_manifests()
    }
    assert listed == on_disk


def _miniature_repo(tmp_path: Path, cargo_version: str) -> Path:
    """A throwaway tree check-version.sh can run against.

    The script reads four files; giving it its own copies is what lets
    these tests exercise the failure paths without mutating the checkout
    the rest of the suite is reading.
    """
    version = read_version()
    (tmp_path / "VERSION").write_text(f"{version}\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "agentcage"\ndynamic = ["version"]\n'
        '\n[tool.hatch.version]\npath = "VERSION"\n'
    )
    (tmp_path / "CHANGELOG.md").write_text(f"## [{version}]\n")
    (tmp_path / "Cargo.toml").write_text(
        f'[workspace]\nmembers = ["rust/agentcage-core"]\n'
        f'\n[workspace.package]\nversion = "{cargo_version}"\n'
    )
    crate = tmp_path / "rust" / "agentcage-core"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "agentcage-core"\nversion.workspace = true\n'
    )
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    shutil.copy2(CHECK_SCRIPT, scripts / "check-version.sh")
    return scripts / "check-version.sh"


def test_check_version_script_accepts_an_agreeing_cargo_workspace(tmp_path):
    script = _miniature_repo(tmp_path, cargo_version=read_version())
    proc = subprocess.run([str(script)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_check_version_script_rejects_a_cargo_version_mismatch(tmp_path):
    """The guard that stops VERSION being bumped without Cargo.toml."""
    script = _miniature_repo(tmp_path, cargo_version="99.99.99")
    proc = subprocess.run([str(script)], capture_output=True, text=True)
    assert proc.returncode != 0
    assert "[workspace.package] version is '99.99.99'" in proc.stderr


def test_check_version_script_rejects_a_crate_pinning_its_own_version(tmp_path):
    script = _miniature_repo(tmp_path, cargo_version=read_version())
    crate = tmp_path / "rust" / "agentcage-core" / "Cargo.toml"
    crate.write_text(
        '[package]\nname = "agentcage-core"\nversion = "0.1.0"\n'
    )
    proc = subprocess.run([str(script)], capture_output=True, text=True)
    assert proc.returncode != 0
    assert "sets a static version" in proc.stderr
