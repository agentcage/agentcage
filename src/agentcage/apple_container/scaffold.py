"""Image building for the apple-container backend.

The host-side ``run_scaffold_setup`` in ``agentcage.init`` invokes
``podman build`` directly on the host. That path is fine for the Linux
container backend, but on macOS there is no host podman — Apple's
`container` CLI is the only builder available. This module mirrors the
container backend's ``build_container_image`` but routes the build through
``ac_cli.run(['build', ...])`` instead.

Called by :meth:`AppleContainerBackend.build_artifacts` BEFORE the per-cage
wrapper image is built — the wrapper's ``FROM <user_image>`` references the
image produced here, so it must exist first.

Crucially, the build reads the cage's OWN staged Containerfile (frozen into
the cage state dir at create), NOT the live scaffold on disk. A scaffold is
a one-shot generator, not a live dependency: an agentcage upgrade that
changes a scaffold therefore can never leak into an existing cage on
``cage update`` — identical to the container/vm backends, which rebuild the
cage's staged Containerfile.
"""

from __future__ import annotations

from pathlib import Path

import click

from agentcage.apple_container import cli as ac_cli


def _base_image_refs(containerfile: Path) -> list[str]:
    """Return the external base-image refs from a Containerfile's ``FROM``
    lines, excluding intra-file multi-stage aliases and the ``scratch``
    pseudo-base.

    A ``FROM <ref> AS <name>`` defines a stage alias; a later ``FROM <name>``
    that references it is not a registry pull, so such refs are dropped.
    Leading build flags (``FROM --platform=... <ref>``) are skipped so the
    real ref is found.

    Used to decide whether ``--pull`` can be honored: a ``localhost/`` base has
    no registry source, so passing ``--pull`` to ``container build`` makes
    BuildKit try to fetch it and fail with ECONNREFUSED (POSIXErrorCode 61).
    """
    stage_aliases: set[str] = set()
    refs: list[str] = []
    try:
        lines = containerfile.read_text().splitlines()
    except OSError:
        return refs
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = [t for t in line.split() if not t.startswith("--")]
        if len(tokens) < 2 or tokens[0].upper() != "FROM":
            continue
        ref = tokens[1]
        alias = tokens[3] if len(tokens) >= 4 and tokens[2].upper() == "AS" else None
        if ref not in stage_aliases and ref.lower() != "scratch":
            refs.append(ref)
        if alias:
            stage_aliases.add(alias)
    return refs


def build_image_from_staged(
    image: str,
    containerfile: Path,
    context_dir: Path,
    build_args: dict[str, str] | None = None,
    *,
    quiet: bool = False,
    no_cache: bool = False,
    pull: bool = False,
) -> None:
    """Build *image* from a cage's staged Containerfile via Apple
    ``container build``.

    *containerfile* / *context_dir* point at the cage's per-cage staged copy
    (in the cage state dir), so the build is frozen to what was captured at
    create time — never the live scaffold.

    Build args are resolved point-in-time exactly as the container backend
    does (untagged registry refs get a concrete tag), so ``--pull`` fetches a
    fresh base without mutating the frozen cage.yaml. ``no_cache`` / ``pull``
    map to ``container build --no-cache`` / ``--pull``.

    ``--pull`` is suppressed when any ``FROM`` in the Containerfile references a
    ``localhost/`` base (e.g. a two-stage scaffold whose cage image is built on
    a locally-built base). Such a ref has no registry source, and Apple
    ``container build --pull`` applies globally to every stage, so BuildKit
    would try to fetch it and fail with ECONNREFUSED (POSIXErrorCode 61). The
    local base's freshness comes from the ``--no-cache`` rebuild instead — the
    same philosophy the backend applies to a ``localhost/`` user image.
    """
    from agentcage.registry import resolve_build_args

    resolved_args, changes = resolve_build_args(dict(build_args or {}))

    def _echo(msg: str) -> None:
        if not quiet:
            click.echo(msg)

    for key, _old, new in changes:
        _echo(f"Build arg {key}: {new}")
    _echo(
        f"Building {image} from {containerfile}"
        f"{' (no-cache)' if no_cache else ''} (apple-container)..."
    )

    effective_pull = pull
    if pull and any(r.startswith("localhost/") for r in _base_image_refs(containerfile)):
        effective_pull = False
        _echo(
            "Skipping --pull: Containerfile has a local-only ('localhost/') "
            "base image with no registry source; --no-cache still forces a "
            "full rebuild."
        )

    argv = ["build", "-t", image, "-f", str(containerfile)]
    if no_cache:
        argv.append("--no-cache")
    if effective_pull:
        argv.append("--pull")
    for k, v in resolved_args.items():
        argv += ["--build-arg", f"{k}={v}"]
    argv.append(str(context_dir))
    ac_cli.run(argv, capture_output=False)
