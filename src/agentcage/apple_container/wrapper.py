"""Per-cage wrapper image generation for the apple-container backend.

For each cage we generate a small Containerfile that layers the agentcage
supervisor + hardening onto the user's cage image. The supervisor is then the
PID 1 of the Apple container microVM and exec's the user's original CMD after
hardening setup.
"""

from __future__ import annotations

import json
import shutil
import tarfile
from pathlib import Path
from typing import Iterable

from jinja2 import FileSystemLoader
from jinja2.sandbox import SandboxedEnvironment

from agentcage.apple_container import cli as ac_cli


_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "apple-container"
# Secret-injection transforms (e.g. google-jwt-bearer) live in the shared
# proxy data dir alongside the container-backend addon. We stage them into
# the apple-container build context so the in-cage mitmproxy addon can
# ``import transforms`` exactly like the container backend's addon does.
_TRANSFORMS_SRC = (
    Path(__file__).resolve().parent.parent / "data" / "proxy" / "transforms"
)


def _user_cmd(user_image: str) -> list[str]:
    """Resolve the user image's effective CMD (ENTRYPOINT + CMD, exec form).

    Apple's `container image inspect` returns the OCI image index plus a
    per-platform variant block; the OCI image config lives at
    ``variants[<host-platform>].config.config`` and uses OCI-style
    capitalized keys (``Cmd``, ``Entrypoint``).
    """
    data = ac_cli.image_inspect(user_image)
    if not data:
        raise ValueError(
            f"cannot inspect user cage image {user_image!r}; is it pulled/built?"
        )

    cfg: dict | None = None
    # Newer Apple schema: data["variants"][i]["config"]["config"]
    variants = data.get("variants") or data.get("Variants")
    if isinstance(variants, list):
        # Prefer the arm64 variant (we're on Apple Silicon); fall back to any.
        for v in variants:
            plat = (v.get("platform") or {})
            if plat.get("architecture") == "arm64":
                cfg = ((v.get("config") or {}).get("config")) or {}
                break
        if cfg is None and variants:
            cfg = ((variants[0].get("config") or {}).get("config")) or {}
    # Older / generic schemas:
    if cfg is None:
        cfg = (
            (data.get("config", {}) or {}).get("config")
            or data.get("config")
            or data.get("Config")
            or {}
        )

    entrypoint = cfg.get("Entrypoint") or cfg.get("entrypoint") or []
    cmd = cfg.get("Cmd") or cfg.get("cmd") or []
    if isinstance(entrypoint, str):
        entrypoint = [entrypoint]
    if isinstance(cmd, str):
        cmd = [cmd]
    combined = [*entrypoint, *cmd]
    if not combined:
        raise ValueError(
            f"user cage image {user_image!r} has neither ENTRYPOINT nor CMD; "
            "agentcage cannot determine what to run"
        )
    return combined


def render_wrapper_containerfile(user_image: str, *, user_cmd: list[str] | None = None) -> str:
    """Render the per-cage wrapper Containerfile to a string."""
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(_DATA_DIR)),
        keep_trailing_newline=True,
    )
    if user_cmd is None:
        user_cmd = _user_cmd(user_image)
    tmpl = env.get_template("Containerfile.wrapper.j2")
    return tmpl.render(user_image=user_image)


def stage_build_context(
    dest: Path,
    user_cmd: list[str],
    allowlist: list[str] | None = None,
    secret_injection_rules: list[dict] | None = None,
) -> None:
    """Stage supervisor + cage CMD + egress filter config into *dest*.

    Files written:
      - supervisor.sh         -- PID 1 of the cage microVM (security-critical)
      - dnsmasq.conf          -- static catch-all DNS rewriter
      - allowlist_addon.py    -- mitmproxy addon (allowlist + audit + injection)
      - cage-cmd.json         -- user image's original ENTRYPOINT+CMD
      - allowlist.txt         -- one host per line
      - secret_injection.json -- list of
                                 ``{env, placeholder, inject_to, transform,
                                 transform_config}`` rules read by the
                                 mitmproxy addon at startup; actual secret
                                 values are env-passed at container run
                                 time so the build context stays free of
                                 secrets.
      - transforms.tar.gz     -- tarball of ``data/proxy/transforms`` so the
                                 in-cage addon can import the same transform
                                 implementations (google-jwt-bearer, ...)
                                 the container backend uses. Rules with no
                                 ``transform`` field never load this code.

    NOTE on the tarball: Apple's ``container build`` (0.5+) silently
    drops the contents when a Containerfile does ``COPY <dir> <dst>``
    — the destination directory exists but is empty. ADD'ing a
    ``.tar.gz`` works because the underlying buildkit path
    auto-extracts archives. We use the OCI image's ADD-extract
    semantics deliberately to dodge the directory-copy bug; if Apple
    ever fixes plain dir COPY we can simplify here.
    """
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(_DATA_DIR / "supervisor.sh", dest / "supervisor.sh")
    shutil.copy2(_DATA_DIR / "dnsmasq.conf", dest / "dnsmasq.conf")
    shutil.copy2(_DATA_DIR / "allowlist_addon.py", dest / "allowlist_addon.py")
    # Pack the transforms package into a deterministic tarball so each
    # rebuild with unchanged source produces a bit-identical artifact
    # (helps Apple's container layer cache; would also help reproducible
    # builds if/when we cross-check image digests in CI). Tarball is
    # small (a few KB) so the .gz / non-.gz choice doesn't matter.
    transforms_archive = dest / "transforms.tar.gz"
    with tarfile.open(transforms_archive, "w:gz") as tar:
        for entry in sorted(_TRANSFORMS_SRC.iterdir()):
            # Skip Python bytecode caches — they're host-local and would
            # bloat the layer for zero functional benefit.
            if entry.name == "__pycache__":
                continue
            # arcname is relative to the archive root so ADD extracts
            # straight into /opt/agentcage/transforms/<file>.
            tar.add(entry, arcname=entry.name)
    (dest / "cage-cmd.json").write_text(json.dumps(user_cmd))
    allow_lines = "\n".join(h.strip() for h in (allowlist or []) if h.strip())
    (dest / "allowlist.txt").write_text(allow_lines + ("\n" if allow_lines else ""))
    (dest / "secret_injection.json").write_text(
        json.dumps(secret_injection_rules or [])
    )


def wrapped_image_name(cage_name: str) -> str:
    """Return the OCI image reference for the wrapped per-cage image."""
    return f"localhost/agentcage-apple-{cage_name}:latest"


def build_wrapper(
    cage_name: str,
    user_image: str,
    *,
    user_cmd: list[str] | None = None,
    allowlist: list[str] | None = None,
    secret_injection_rules: list[dict] | None = None,
) -> str:
    """Generate Containerfile, stage build context, run `container build`.

    Returns the built image reference.
    """
    import tempfile

    image = wrapped_image_name(cage_name)
    containerfile = render_wrapper_containerfile(user_image, user_cmd=user_cmd)

    if user_cmd is None:
        user_cmd = _user_cmd(user_image)

    with tempfile.TemporaryDirectory(prefix="agentcage-apple-build-") as tmp:
        tmpdir = Path(tmp)
        (tmpdir / "Containerfile").write_text(containerfile)
        stage_build_context(
            tmpdir, user_cmd, allowlist=allowlist,
            secret_injection_rules=secret_injection_rules,
        )
        ac_cli.run(
            ["build", "-t", image, "-f", str(tmpdir / "Containerfile"), str(tmpdir)],
            capture_output=False,  # stream output to user
        )
    return image


def collect_image_artifacts(cage_name: str) -> Iterable[str]:
    """Return image references owned by *cage_name* (for cleanup)."""
    yield wrapped_image_name(cage_name)
