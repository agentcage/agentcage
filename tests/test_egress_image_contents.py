"""Static checks that the egress image actually ships the addon's code.

These are deliberately podman-free (unlike ``test_egress_image.py``, whose
whole module is gated on ``REQUIRES_PODMAN`` and therefore skips on a macOS
dev host) because the bug they guard is a *packaging* bug, not a runtime one.

``policy_api.py`` was added to ``data/proxy/`` without a matching ``COPY`` in
``Containerfile.egress``. Every layer of the existing suite passed: the config
parsed, the quadlets rendered, the image built cleanly. But the module was
absent at runtime, ``addon.py`` swallowed the ImportError as
``domains.auto init failed: No module named 'policy_api'``, and the entire
feature was inert on every backend while the cage still reported healthy.

A build-time smoke test cannot catch this either — the image builds fine when
a file is simply missing. The only cheap guard is asserting the Containerfile
copies what the addon imports.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "src" / "agentcage" / "data"
CONTAINERFILE = DATA_DIR / "containers" / "Containerfile.egress"
PROXY_DIR = DATA_DIR / "proxy"


def _copied_paths() -> set[str]:
    """Every source path named by a COPY in Containerfile.egress."""
    copied: set[str] = set()
    for line in CONTAINERFILE.read_text().splitlines():
        line = line.strip()
        if not line.upper().startswith("COPY "):
            continue
        # `COPY <src>... <dest>` — the last token is the destination, and
        # line continuations are already folded out by the simple form the
        # file uses today.
        tokens = line[len("COPY "):].split()
        for token in tokens[:-1]:
            copied.add(token.rstrip("/"))
    return copied


def test_every_proxy_module_is_copied_into_the_image():
    """No top-level proxy/*.py may be left out of the egress image.

    The addon puts its own directory on sys.path and imports its siblings by
    bare module name, so a module that exists in the repo but not in the
    image fails only at runtime, inside a container, as a caught ImportError.
    """
    copied = _copied_paths()
    missing = []
    for module in sorted(PROXY_DIR.glob("*.py")):
        rel = f"proxy/{module.name}"
        # A module is shipped either by its own COPY or by a COPY of the
        # whole proxy/ directory.
        if rel not in copied and "proxy" not in copied:
            missing.append(rel)
    assert not missing, (
        f"{missing} exist under data/proxy/ but are never COPYed in "
        f"Containerfile.egress — they will be absent at runtime and the "
        f"addon will degrade with a caught ImportError"
    )


def test_addon_local_imports_are_shipped():
    """Modules ``addon.py`` imports by bare name must be in the image.

    Complements the glob test above: this one is anchored to what the addon
    actually imports, so a module moved out of ``proxy/`` but still imported
    is caught too.
    """
    addon = (PROXY_DIR / "addon.py").read_text()
    # Local sibling imports look like `from policy_api import X` or
    # `import policy_api` — bare names that resolve via the script dir.
    local_names = set()
    for match in re.finditer(
        r"^\s*(?:from|import)\s+([a-z_][a-z0-9_]*)", addon, re.MULTILINE
    ):
        name = match.group(1)
        if (PROXY_DIR / f"{name}.py").exists():
            local_names.add(name)

    assert "policy_api" in local_names, (
        "expected addon.py to import policy_api; update this test if the "
        "module was intentionally renamed"
    )

    copied = _copied_paths()
    for name in sorted(local_names):
        assert f"proxy/{name}.py" in copied or "proxy" in copied, (
            f"addon.py imports {name!r} but Containerfile.egress never "
            f"COPYs proxy/{name}.py into the image"
        )


def test_egress_gets_the_agentcage_version():
    """The addon reports a version in its introspection payloads.

    ``policy_api`` reads ``AGENTCAGE_VERSION`` from the egress environment;
    the quadlet is where that gets set for the container/vm backends. Without
    it every ``/v1/health`` and ``/v1/allowlist`` response carried
    ``"version": ""``.
    """
    template = (
        REPO_ROOT / "src" / "agentcage" / "templates" / "egress.container.j2"
    ).read_text()
    assert "AGENTCAGE_VERSION" in template
