"""The egress content hash is a pinned cross-language contract.

``agentcage.egress_hash`` computes the digest that becomes the shared
egress image's tag, ``localhost/agentcage-egress:<version>-<12 hex>``.
That tag is what makes an in-release fix to the egress image actually
reach a host (#312): the build short-circuits when the tag is already
present, so before the hash existed a host could keep running a pre-fix
supervisor with a world-readable ``audit.jsonl`` while ``cage create``
printed "already present; skipping rebuild".

The Rust port (RUST-PORT-PLAN §2.1) keeps the egress image Python but
moves the host CLI to Rust, where the build context is extracted from
bytes embedded in the binary. Its digest must equal this one **byte for
byte**. If it does not, every Mac rebuilds its egress image once on
upgrade and then carries a tag lineage the Python build never produces.

So the digest is pinned in ``tests/fixtures/egress_hash.json`` rather than
merely asserted to be self-consistent. The fixture also records the full
sorted ``(relpath, size)`` input list, because "the hash changed" is not a
useful failure: the input list says *which* files entered or left the
image. A future Rust test should check itself against the same fixture.

Re-blessing the fixture must be deliberate — ``scripts/bless-egress-hash.py``,
and only for an intended change to the egress build inputs.

The synthetic cases below build their own data dir under ``tmp_path``
instead of touching the real tree.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from agentcage import egress_hash


FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "egress_hash.json"

_BLESS_HINT = (
    "If this change to the egress build inputs is intended, re-bless the "
    "fixture with `python3 scripts/bless-egress-hash.py` — deliberately, "
    "and in the same commit as the change that moved it. If it is not "
    "intended, something entered or left the egress image by accident."
)


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


# ── the pin ────────────────────────────────────────────────


class TestPinnedFixture:
    def test_live_hash_matches_fixture(self, fixture: dict):
        """THE cross-language pin: this exact hex is what Rust must produce."""
        live = egress_hash.egress_content_hash()
        assert live == fixture["hash"], (
            f"egress content hash moved: {fixture['hash']} -> {live}. "
            f"{_BLESS_HINT}"
        )

    def test_build_inputs_match_fixture(self, fixture: dict):
        """The input list, in the hash's own sort order, with sizes.

        Pinned separately from the digest so a failure names the files
        that moved rather than just reporting twelve different hex chars.
        """
        live = {
            rel: path.stat().st_size
            for rel, path in egress_hash.egress_build_inputs()
        }
        expected = fixture["inputs"]

        added = sorted(set(live) - set(expected))
        removed = sorted(set(expected) - set(live))
        assert not added and not removed, (
            f"egress build inputs changed — added: {added}, "
            f"removed: {removed}. {_BLESS_HINT}"
        )
        assert live == expected, _BLESS_HINT
        # Order is part of the contract: the digest is taken over the
        # inputs sorted by POSIX relative path, so it must never depend on
        # filesystem iteration order.
        assert list(live) == list(expected) == sorted(expected)
        assert len(live) == fixture["input_count"]

    def test_hash_shape(self, fixture: dict):
        assert len(fixture["hash"]) == egress_hash.TAG_HASH_LEN
        assert all(c in "0123456789abcdef" for c in fixture["hash"])


# ── determinism ────────────────────────────────────────────


class TestDeterminism:
    def test_same_result_twice(self):
        assert egress_hash.egress_content_hash() == \
            egress_hash.egress_content_hash()

    def test_build_inputs_stable_across_calls(self):
        assert egress_hash.egress_build_inputs() == \
            egress_hash.egress_build_inputs()


# ── synthetic build contexts (never the real tree) ─────────


def _fake_data_dir(tmp_path: Path) -> Path:
    """A miniature build context with the same shape as the real one."""
    root = tmp_path / "data"
    (root / "containers").mkdir(parents=True)
    (root / "proxy" / "inspectors").mkdir(parents=True)

    (root / "containers" / "Containerfile.egress").write_text(textwrap.dedent("""\
        FROM docker.io/mitmproxy/mitmproxy@sha256:deadbeef
        # a comment mentioning COPY that must not be parsed
        COPY proxy/addon.py /opt/agentcage/addon.py
        COPY proxy/inspectors/ /opt/agentcage/inspectors/
        COPY containers/supervisor-egress.sh \\
             /opt/agentcage/supervisor
    """))
    (root / "containers" / "supervisor-egress.sh").write_text("#!/bin/sh\nexec mitmdump\n")
    (root / "proxy" / "addon.py").write_text("class Agentcage:\n    pass\n")
    (root / "proxy" / "inspectors" / "domain.py").write_text("ALLOW = []\n")
    return root


class TestSyntheticContext:
    def test_copied_file_change_changes_hash(self, tmp_path: Path):
        root = _fake_data_dir(tmp_path)
        before = egress_hash.egress_content_hash(root)
        sup = root / "containers" / "supervisor-egress.sh"
        sup.write_text(sup.read_text() + "# chmod 0640 audit.jsonl\n")
        assert egress_hash.egress_content_hash(root) != before

    def test_uncopied_file_does_not_change_hash(self, tmp_path: Path):
        """Stability half of #312: a file sitting in the build context that
        the egress Containerfile never COPYs must not force a rebuild.

        ``Containerfile.helper`` used to be the real instance — shipped
        in ``data/containers/`` and named by no egress ``COPY``. It was
        deleted at the cutover (RUST-PORT-PLAN.md §2.4: it was an alpine
        image whose only content was ``python3`` and ``py3-yaml``, built
        by nothing), so the case is now synthetic. The property it pins
        is not: ``Containerfile.nested`` is in the same position today.
        """
        root = _fake_data_dir(tmp_path)
        before = egress_hash.egress_content_hash(root)

        (root / "containers" / "Containerfile.helper").write_text(
            "FROM alpine\nRUN apk add python3 py3-yaml\n"
        )
        (root / "unrelated.txt").write_text("scratch\n")
        (root / "proxy" / "not_copied.py").write_text("# sibling of addon.py\n")

        after = egress_hash.egress_content_hash(root)
        assert after == before
        rels = {rel for rel, _ in egress_hash.egress_build_inputs(root)}
        assert "containers/Containerfile.helper" not in rels
        assert "proxy/not_copied.py" not in rels

    def test_bytecode_caches_excluded(self, tmp_path: Path):
        """__pycache__/.pyc are interpreter-dependent; hashing them would
        make the tag differ across Python versions for identical sources —
        and would be unreproducible from Rust, which has no __pycache__."""
        root = _fake_data_dir(tmp_path)
        before = egress_hash.egress_content_hash(root)

        cache = root / "proxy" / "inspectors" / "__pycache__"
        cache.mkdir()
        (cache / "domain.cpython-313.pyc").write_bytes(b"\xcb\x0c\x0d\x0a")
        (root / "proxy" / "inspectors" / "stray.pyc").write_bytes(b"\x00")
        (root / "proxy" / "inspectors" / "stray.pyo").write_bytes(b"\x00")

        assert egress_hash.egress_content_hash(root) == before
        rels = {rel for rel, _ in egress_hash.egress_build_inputs(root)}
        assert not any("__pycache__" in rel for rel in rels)
        assert not any(rel.endswith((".pyc", ".pyo")) for rel in rels)

    def test_rename_changes_hash(self, tmp_path: Path):
        """Paths are hashed next to the bytes, so a pure rename inside a
        COPYed directory still invalidates the tag."""
        root = _fake_data_dir(tmp_path)
        before = egress_hash.egress_content_hash(root)
        inspectors = root / "proxy" / "inspectors"
        (inspectors / "domain.py").rename(inspectors / "domain_v2.py")
        assert egress_hash.egress_content_hash(root) != before

    def test_new_copy_source_joins_the_hash(self, tmp_path: Path):
        """The COPY list is parsed, not hardcoded: adding a source pulls
        the file into the digest (and, via the fixture, into review)."""
        root = _fake_data_dir(tmp_path)
        (root / "proxy" / "watcher.py").write_text("# watcher\n")
        assert "proxy/watcher.py" not in {
            rel for rel, _ in egress_hash.egress_build_inputs(root)
        }

        cf = root / "containers" / "Containerfile.egress"
        cf.write_text(cf.read_text() + "COPY proxy/watcher.py /opt/agentcage/watcher.py\n")
        assert "proxy/watcher.py" in {
            rel for rel, _ in egress_hash.egress_build_inputs(root)
        }

    def test_missing_containerfile(self, tmp_path: Path):
        assert egress_hash.egress_build_inputs(tmp_path) == []
        assert egress_hash.egress_content_hash(tmp_path) == egress_hash.UNKNOWN_HASH


# ── the module stays portable ──────────────────────────────


class TestStandaloneModule:
    def test_imports_nothing_from_agentcage(self):
        """A Rust conformance test and a non-macOS caller both need this
        module without dragging in the apple-container backend (or click)."""
        source = Path(egress_hash.__file__).read_text()
        offenders = [
            line for line in source.splitlines()
            if (line.startswith("import ") or line.startswith("from "))
            and ("agentcage" in line or "click" in line)
        ]
        assert not offenders, offenders

    def test_backend_reexports_stay_wired(self):
        """``apple_container`` keeps the private names it always had, so
        its own tests (and the monkeypatch seam in them) keep working."""
        ac = pytest.importorskip("agentcage.backends.apple_container")
        assert ac._egress_content_hash is egress_hash.egress_content_hash
        assert ac._egress_build_inputs is egress_hash.egress_build_inputs
        assert ac._egress_copy_sources is egress_hash.egress_copy_sources
        assert ac._egress_data_dir is egress_hash.egress_data_dir
        assert ac._EGRESS_TAG_HASH_LEN == egress_hash.TAG_HASH_LEN
        assert ac._egress_image_name().endswith(
            f"-{egress_hash.egress_content_hash()}"
        )
