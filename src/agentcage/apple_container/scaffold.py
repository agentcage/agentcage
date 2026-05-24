"""Scaffold image building for the apple-container backend.

The host-side ``run_scaffold_setup`` in ``agentcage.init`` invokes
``podman build`` directly on the host. That path is fine for the Linux
container backend, but on macOS there is no host podman — Apple's
`container` CLI is the only builder available. This module mirrors the
``run_scaffold_setup`` logic but routes every build through
``ac_cli.run(['build', ...])`` instead.

Called by :meth:`AppleContainerBackend.build_artifacts` BEFORE the
per-cage wrapper image is built — the wrapper's ``FROM <user_image>``
references the scaffold-built image, so it must exist first.
"""

from __future__ import annotations

import click

from agentcage.apple_container import cli as ac_cli
from agentcage.init import load_scaffold_meta, resolve_scaffold


def build_scaffold_images(scaffold: str, *, quiet: bool = False) -> None:
    """Build every image declared in *scaffold*'s ``scaffold.yaml``.

    Mirrors the surface of :func:`agentcage.init.run_scaffold_setup`
    but builds via Apple ``container build`` rather than host podman.
    Build args, cap-add hints, and the "skip if image exists" check
    all carry over.

    No-op when *scaffold* is empty (cage.yaml without a scaffold).
    """
    if not scaffold:
        return
    meta = load_scaffold_meta(scaffold)
    if meta is None:
        return
    scaffold_dir = resolve_scaffold(scaffold)
    if scaffold_dir is None:
        return

    def _echo(msg: str) -> None:
        if not quiet:
            click.echo(msg)

    for entry in meta.get("build", []):
        image = entry["image"]
        if ac_cli.image_inspect(image):
            _echo(f"Image {image} already exists, skipping build.")
            continue
        if "containerfile" not in entry:
            # The host podman flow supports other build types (pull,
            # registry tag) — apple-container backend only handles
            # local Containerfile builds in v1. Anything else is a no-op
            # here and the wrapper build will fail later with a clear
            # "image not found" error.
            _echo(f"warning: scaffold entry for {image!r} has no containerfile; skipping")
            continue
        containerfile = str(scaffold_dir / entry["containerfile"])
        _echo(f"Building {image} (apple-container)...")
        argv = ["build", "-t", image, "-f", containerfile]
        # build_args are scaffold-resolved templating, e.g. registry tags.
        # Apple's `container build` accepts --build-arg KEY=VALUE.
        for k, v in (entry.get("build_args") or {}).items():
            argv += ["--build-arg", f"{k}={v}"]
        argv.append(str(scaffold_dir))
        ac_cli.run(argv, capture_output=False)
