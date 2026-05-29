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

    argv = ["build", "-t", image, "-f", str(containerfile)]
    if no_cache:
        argv.append("--no-cache")
    if pull:
        argv.append("--pull")
    for k, v in resolved_args.items():
        argv += ["--build-arg", f"{k}={v}"]
    argv.append(str(context_dir))
    ac_cli.run(argv, capture_output=False)
