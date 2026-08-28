"""Tests for the content-addressed tag of the shared agentcage-egress image.

``_build_egress_image_if_missing()`` short-circuits when the egress image
tag is already present on the host. While the tag was ``agentcage-egress:
<version>`` alone, that short-circuit swallowed every in-release change to
the image: a host holding ``agentcage-egress:0.32.0`` built before the
0640 proxy-log hardening (#186) kept running the pre-fix supervisor, and
`cage create` printed "already present; skipping rebuild". Measured on a
real Mac: ``grep -c _ensure_log /opt/agentcage/supervisor`` inside the
running egress VM returned 0 and ``audit.jsonl`` was mode 0644, until
``--no-cache`` forced a rebuild (then 9, and 0640).

The tag now carries a hash of the actual build inputs — the Containerfile
plus every file it COPYs — so a changed supervisor produces a tag the
host cannot have, and the rebuild happens with no flag. These tests pin
that property, plus the stability half of it (unrelated churn in the
build context must NOT invalidate the tag and force pointless rebuilds).

Offline: no `container` CLI, no image build. The real build context is
copied into tmp_path and the backend is pointed at the copy.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from agentcage.apple_container import cli as ac_cli
from agentcage.backends import apple_container as ac_backend
from agentcage.backends.apple_container import AppleContainerBackend


REAL_DATA_DIR = Path(ac_backend.__file__).resolve().parent.parent / "data"

# Files the Containerfile COPYs today. Not the source of truth (the
# helpers parse the Containerfile), just a canary that the parser keeps
# seeing the security-relevant inputs.
_EXPECTED_INPUTS = {
    "containers/Containerfile.egress",
    "containers/supervisor-egress.sh",
    "containers/dns-audit.sh",
    "proxy/addon.py",
    "proxy/capture.py",
    "proxy/secret_injector.py",
    "proxy/inspectors/secrets.py",
    "proxy/relays/smtp.py",
    "proxy/transforms/google_jwt_bearer.py",
}


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    """A writable copy of the real egress build context."""
    dest = tmp_path / "data"
    shutil.copytree(REAL_DATA_DIR, dest)
    return dest


def _supervisor(data_dir: Path) -> Path:
    return data_dir / "containers" / "supervisor-egress.sh"


# ── build inputs: what actually feeds the hash ──────────────


class TestEgressBuildInputs:
    def test_covers_every_copied_file(self):
        """The COPY directives are parsed out of the real Containerfile, so
        the supervisor and the whole addon tree are hashed."""
        rels = {rel for rel, _ in ac_backend._egress_build_inputs()}
        missing = _EXPECTED_INPUTS - rels
        assert not missing, f"egress build inputs miss COPYed files: {missing}"

    def test_excludes_bytecode_caches(self, data_dir: Path):
        """__pycache__ is interpreter-dependent; hashing it would make the
        tag unstable across Python versions for identical sources."""
        cache = data_dir / "proxy" / "inspectors" / "__pycache__"
        cache.mkdir(exist_ok=True)
        (cache / "domain.cpython-313.pyc").write_bytes(b"\x00\x01")
        rels = {rel for rel, _ in ac_backend._egress_build_inputs(data_dir)}
        assert not any("__pycache__" in rel for rel in rels)

    def test_missing_containerfile_yields_no_inputs(self, tmp_path: Path):
        assert ac_backend._egress_build_inputs(tmp_path) == []
        assert ac_backend._egress_content_hash(tmp_path) == "unknown"


# ── the hash itself ────────────────────────────────────────


class TestEgressContentHash:
    def test_stable_across_calls(self, data_dir: Path):
        assert ac_backend._egress_content_hash(data_dir) == \
            ac_backend._egress_content_hash(data_dir)

    def test_supervisor_change_changes_hash(self, data_dir: Path):
        """THE regression: editing supervisor-egress.sh must move the hash.

        This is the #186 shape — a permission fix inside the supervisor
        with no version bump.
        """
        before = ac_backend._egress_content_hash(data_dir)
        sup = _supervisor(data_dir)
        sup.write_text(sup.read_text() + "\n# _ensure_log tightening\n")
        after = ac_backend._egress_content_hash(data_dir)
        assert after != before

    def test_revert_restores_hash(self, data_dir: Path):
        """Content-addressed, not monotonic: reverting the edit returns the
        original tag, so a downgrade reuses the already-built image."""
        original = _supervisor(data_dir).read_text()
        before = ac_backend._egress_content_hash(data_dir)
        _supervisor(data_dir).write_text(original + "\n# churn\n")
        assert ac_backend._egress_content_hash(data_dir) != before
        _supervisor(data_dir).write_text(original)
        assert ac_backend._egress_content_hash(data_dir) == before

    def test_containerfile_change_changes_hash(self, data_dir: Path):
        before = ac_backend._egress_content_hash(data_dir)
        cf = data_dir / "containers" / "Containerfile.egress"
        cf.write_text(cf.read_text() + "\nENV AGENTCAGE_EGRESS_MARKER=1\n")
        assert ac_backend._egress_content_hash(data_dir) != before

    def test_addon_change_changes_hash(self, data_dir: Path):
        """The proxy tree ships in the image too — an inspector fix must
        rebuild just like a supervisor fix."""
        before = ac_backend._egress_content_hash(data_dir)
        inspector = data_dir / "proxy" / "inspectors" / "secrets.py"
        inspector.write_text(inspector.read_text() + "\n# tightened\n")
        assert ac_backend._egress_content_hash(data_dir) != before

    def test_rename_changes_hash(self, data_dir: Path):
        """Paths are hashed alongside contents, so a pure rename inside a
        COPYed directory still invalidates the tag."""
        before = ac_backend._egress_content_hash(data_dir)
        inspectors = data_dir / "proxy" / "inspectors"
        (inspectors / "entropy.py").rename(inspectors / "entropy_v2.py")
        assert ac_backend._egress_content_hash(data_dir) != before

    def test_unrelated_file_does_not_change_hash(self, data_dir: Path):
        """Stability half: files in the build context that the egress
        Containerfile never COPYs must not force needless rebuilds."""
        before = ac_backend._egress_content_hash(data_dir)
        (data_dir / "containers" / "Containerfile.helper").write_text(
            "FROM scratch\n# unrelated image\n"
        )
        (data_dir / "apple-container" / "cage-init.sh").write_text("#!/bin/sh\n")
        assert ac_backend._egress_content_hash(data_dir) == before


# ── the tag ────────────────────────────────────────────────


class TestEgressImageName:
    def test_tag_shape(self):
        """localhost/agentcage-egress:<version>-<12 hex>."""
        name = ac_backend._egress_image_name()
        repo, _, tag = name.rpartition(":")
        assert repo == "localhost/agentcage-egress"
        assert re.fullmatch(r".+-[0-9a-f]{12}", tag), tag

    def test_tag_embeds_content_hash(self, data_dir: Path):
        assert ac_backend._egress_image_name(data_dir).endswith(
            f"-{ac_backend._egress_content_hash(data_dir)}"
        )

    def test_tag_moves_with_supervisor(self, data_dir: Path):
        before = ac_backend._egress_image_name(data_dir)
        sup = _supervisor(data_dir)
        sup.write_text(sup.read_text() + "\n# chmod 0640\n")
        assert ac_backend._egress_image_name(data_dir) != before


# ── the rebuild decision ───────────────────────────────────


def _fake_run(calls):
    def run(argv, **kwargs):  # noqa: ARG001
        calls.append(argv)
        return type("CP", (), {"returncode": 0, "stdout": "", "stderr": ""})()
    return run


class TestRebuildDecision:
    def test_stale_supervisor_rebuilds_without_flags(self, data_dir, monkeypatch):
        """The bug, end to end: a host holding the tag built from the OLD
        supervisor must rebuild once the supervisor changes — with no
        --no-cache and no --pull."""
        monkeypatch.setattr(ac_backend, "_egress_data_dir", lambda: data_dir)
        stale_tag = ac_backend._egress_image_name(data_dir)

        sup = _supervisor(data_dir)
        sup.write_text(sup.read_text() + "\n# _ensure_log 0640\n")
        fresh_tag = ac_backend._egress_image_name(data_dir)
        assert fresh_tag != stale_tag

        calls: list[list[str]] = []
        backend = AppleContainerBackend()
        with patch.object(ac_cli, "run", side_effect=_fake_run(calls)), \
             patch.object(ac_cli, "image_inspect",
                          side_effect=lambda ref: {"Id": "sha256:old"}
                          if ref == stale_tag else None):
            backend._build_egress_image_if_missing(quiet=True)

        builds = [a for a in calls if a[:1] == ["build"]]
        assert builds, "a changed supervisor must rebuild the egress image"
        assert fresh_tag in builds[0]
        assert stale_tag not in builds[0]
        # Still a plain cached build — the tag change is what forces the
        # rebuild, so we must not have quietly turned on --no-cache.
        assert "--no-cache" not in builds[0]
        assert "--pull" not in builds[0]

    def test_unchanged_inputs_still_skip(self, data_dir, monkeypatch):
        """The cost-saving skip survives: an unmodified build context with
        the matching tag present does not rebuild."""
        monkeypatch.setattr(ac_backend, "_egress_data_dir", lambda: data_dir)
        tag = ac_backend._egress_image_name(data_dir)

        calls: list[list[str]] = []
        backend = AppleContainerBackend()
        with patch.object(ac_cli, "run", side_effect=_fake_run(calls)), \
             patch.object(ac_cli, "image_inspect",
                          side_effect=lambda ref: {"Id": "sha256:cur"}
                          if ref == tag else None):
            backend._build_egress_image_if_missing(quiet=True)

        assert not calls, "unchanged inputs must reuse the cached egress image"

    def test_build_uses_the_hashed_tag_and_real_context(self, data_dir, monkeypatch):
        """The tag that gets built is the tag `start()` later demands, and
        the build context is the data dir the hash was taken over."""
        monkeypatch.setattr(ac_backend, "_egress_data_dir", lambda: data_dir)
        calls: list[list[str]] = []
        backend = AppleContainerBackend()
        with patch.object(ac_cli, "run", side_effect=_fake_run(calls)), \
             patch.object(ac_cli, "image_inspect", return_value=None):
            backend._build_egress_image_if_missing(quiet=True)

        build = next(a for a in calls if a[:1] == ["build"])
        assert build[build.index("-t") + 1] == ac_backend._egress_image_name()
        assert build[-1] == str(data_dir.resolve())
        assert build[build.index("-f") + 1] == str(
            data_dir / "containers" / "Containerfile.egress"
        )


# ── COPY parsing helpers ───────────────────────────────────


class TestCopySourceParsing:
    def test_flags_and_multiple_sources(self):
        srcs = ac_backend._egress_copy_sources(
            "COPY --chown=1000:1000 a.py b.py /opt/agentcage/\n"
        )
        assert srcs == ["a.py", "b.py"]

    def test_line_continuation(self):
        srcs = ac_backend._egress_copy_sources(
            "COPY proxy/addon.py \\\n     proxy/capture.py \\\n     /opt/agentcage/\n"
        )
        assert srcs == ["proxy/addon.py", "proxy/capture.py"]

    def test_comments_and_other_instructions_ignored(self):
        srcs = ac_backend._egress_copy_sources(
            "# COPY not/a/real/file /x\nRUN echo COPY nope /x\nCOPY real.sh /x\n"
        )
        assert srcs == ["real.sh"]

    def test_context_escape_is_dropped(self, data_dir: Path):
        """A `COPY ../secret …` cannot be part of the hash (nor of the
        build) — it must not raise or reach outside the context."""
        cf = data_dir / "containers" / "Containerfile.egress"
        cf.write_text(cf.read_text() + "\nCOPY ../../../etc/passwd /tmp/x\n")
        rels = {rel for rel, _ in ac_backend._egress_build_inputs(data_dir)}
        assert all(not rel.startswith("..") for rel in rels)
