#!/usr/bin/env python3
"""Record what the apple-container backend derives from a cage.yaml.

`backends/apple_container.py` is the largest backend in the tree and it is
the only one with **no golden-corpus units**: every apple case under
`tests/fixtures/golden/valid/` carries a `quadlets/NOT-APPLICABLE.txt`,
because that backend builds `container run` argv and a launchd plist inside
itself rather than going through the quadlet renderer (PR C8 said so and
handed the gap to Track E).  This closes the *generation-half-A* part of
that gap — image naming, the egress content-hash wiring,
`_render_egress_config`, `_user_volume_argv`, `_tmpfs_targets` and
`_tmpfs_copyup_seeds` — the same way every other fixture in this port is
made: by driving the **real Python** and recording what it produced.

Nothing here needs a Mac.  `platform.system()` is patched to `"Darwin"`
before `agentcage` is imported, which is exactly what
`tests/test_apple_container.py:44` has always done — there is no macOS
runner in CI and there never has been.  The execution half
(`start`/`stop`/`_stage_secrets`/mask-mountpoint cleanup) is PR E5 and a
manual `phase_apple.sh` gate; none of it is touched here.

Run it with::

    uv run python scripts/gen-apple-container-fixtures.py           # write
    uv run python scripts/gen-apple-container-fixtures.py --check   # verify

The inputs are curated; the EXPECTATIONS are always computed, never typed.
A behaviour change shows up as a fixture diff in review rather than as
silent drift between the Python and the Rust port.

Determinism
-----------
Everything host-specific is pinned or scrubbed:

* ``HOME``/``XDG_*`` point into a throwaway tree, resolved through
  ``realpath`` first so a symlinked ``/tmp`` cannot leak in;
* the sandbox root is scrubbed to ``{{ROOT}}`` on the way out, and the
  package version to ``{{VERSION}}`` (``scripts/check-version.sh`` is what
  holds the Rust side's `CARGO_PKG_VERSION` equal to it);
* the egress content hash is **not** scrubbed.  It is a frozen
  cross-language contract (`src/agentcage/egress_hash.py`,
  `tests/fixtures/egress_hash.json`) and a diff in it is the whole point.

A testing hazard worth stating outright, because it bit this script:
``AppleContainerBackend._state_dir`` expands ``~`` **directly** and ignores
``XDG_CONFIG_HOME``.  An XDG-only sandbox does not redirect it, so ``HOME``
has to be set too or the generator writes into the developer's real home.
``state-paths.json`` pins that asymmetry deliberately — see
RUST-PORT-PLAN.md section 2.7.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_OUT = _ROOT / "tests" / "fixtures" / "apple-container"
_CORPUS = _ROOT / "tests" / "fixtures" / "golden" / "valid"

# The corpus cases whose cage.yaml this script re-renders.  Reusing them
# rather than inventing new inputs keeps one reviewed set of apple configs
# in the tree, and it is the same set that carries NOT-APPLICABLE.txt.
_CORPUS_CASES = [
    "backend-apple-container",
    "backend-apple-container-autostart",
    "backend-apple-container-copyup-unseedable",
    "backend-apple-container-drops",
    "backend-apple-container-inspectors",
]

# `_state_dir` ignores XDG_CONFIG_HOME, so the XDG roots are deliberately
# put somewhere HOME is not: a fixture generated with the two agreeing
# could not tell the wart from correct behaviour.
_XDG_SUBDIR = "xdg"

_SCRUB_ROOT = "{{ROOT}}"
_SCRUB_VERSION = "{{VERSION}}"
_SCRUB_CONTEXT = "{{CONTEXT}}"


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

# The resolvers the corpus pins, reused here so a cage.yaml with no
# `dns_servers:` renders the same file on every machine. Without this the
# generator records whatever is in the developer's /etc/resolv.conf — a
# Tailscale address, in the case that caught it.
_FROZEN_DNS_SERVERS = ["192.0.2.53", "192.0.2.54"]

# `secrets.scope: auto` otherwise shells out to systemd-creds.
_FROZEN_CREDS_SCOPE = "user"


def _install_determinism_patches() -> None:
    """Make this process look like an Apple Silicon Mac, deterministically.

    The platform patch must land before ``agentcage.config`` is imported:
    ``default_isolation`` and ``validate_config`` both branch on
    ``platform.system()``, and the apple-container isolation is refused
    outright on Linux.

    The package version is deliberately **not** frozen, unlike the golden
    corpus's. The egress image tag is the thing under test here and it is
    `<version>-<hash>`; pinning the version to a fake would record a tag no
    user could ever have. It is scrubbed to `{{VERSION}}` on the way out
    instead, and `scripts/check-version.sh` is what holds the Rust side's
    `CARGO_PKG_VERSION` equal to the VERSION file.
    """
    platform.system = lambda: "Darwin"
    platform.machine = lambda: "arm64"
    platform.mac_ver = lambda: ("26.0", ("", "", ""), "arm64")

    import agentcage.config as config
    import agentcage.secret_resolver as secret_resolver

    config._host_dns_servers = lambda: list(_FROZEN_DNS_SERVERS)
    secret_resolver.detect_default_scope = lambda: _FROZEN_CREDS_SCOPE


def _build_sandbox(work: Path) -> tuple[Path, dict[str, str]]:
    """Create the throwaway HOME/XDG tree and return ``(root, env)``.

    ``state.py`` resolves ``XDG_CONFIG_HOME``/``XDG_DATA_HOME`` at *import*
    time, so this has to run before ``agentcage.state`` is imported.
    """
    root = Path(os.path.realpath(work))
    home = root / "home"
    # The layout every volume/tmpfs case below is written against.  It is
    # global rather than per-case so the Rust side materializes it once.
    for rel in _TREE_DIRS:
        (root / rel).mkdir(parents=True, exist_ok=True)
    for link, target in _TREE_SYMLINKS.items():
        path = root / link
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.is_symlink():
            path.symlink_to(target)

    env = {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(root / _XDG_SUBDIR / "config"),
        "XDG_DATA_HOME": str(root / _XDG_SUBDIR / "data"),
        "XDG_RUNTIME_DIR": str(root / _XDG_SUBDIR / "run"),
        "TZ": "UTC",
        # One variable deliberately set and one deliberately absent, so
        # both halves of `_user_volume_argv`'s expandvars branch are
        # reachable.  `APPLE_FIXTURE_UNSET` is popped below.
        "APPLE_FIXTURE_DIR": str(home / "work"),
    }
    os.environ.pop("APPLE_FIXTURE_UNSET", None)
    os.environ.update(env)
    return root, env


# Directories the fixture tree carries, relative to the sandbox root.
_TREE_DIRS = [
    "home",
    "home/work",
    "home/work/sub",
    "home/project",
    "home/project/.claude",
    "home/project/.git",
    "home/project/.git/hooks",
    "home/project/nested",
    "outside",
    "outside/secret",
    f"{_XDG_SUBDIR}/config",
    f"{_XDG_SUBDIR}/data",
    f"{_XDG_SUBDIR}/run",
]

# Symlinks the fixture tree carries.  Both point *out* of the home
# directory: one at the volume level (caught by `_user_volume_argv`'s
# realpath-inside-home check) and one at the mask level (caught by
# `_tmpfs_copyup_seeds`'s resolves-inside-the-bind check).  Relative
# targets so the tree is relocatable.
_TREE_SYMLINKS = {
    "home/escape": "../outside",
    "home/project/.evil": "../../outside/secret",
}


class Scrubber:
    """Replaces the sandbox root and the package version with tokens."""

    def __init__(self, root: Path, version: str) -> None:
        self._root = str(root)
        self._version = version

    def text(self, value: str) -> str:
        out = value.replace(self._root, _SCRUB_ROOT)
        return out.replace(self._version, _SCRUB_VERSION)

    def value(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {self.value(k): self.value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.value(v) for v in value]
        return value


def _assert_no_leaks(text: str, root: Path) -> None:
    """Fail loudly if an unscrubbed absolute sandbox path survived."""
    if str(root) in text:
        raise SystemExit(
            f"fixture leaks the sandbox root {root} — add a scrub for it"
        )


# ---------------------------------------------------------------------------
# Case tables
# ---------------------------------------------------------------------------

def _volume_cases() -> list[dict]:
    """The curated `container.volumes` / `container.tmpfs` inputs.

    Every case runs all four pure helpers, so one table covers
    `_user_volume_argv`, `_tmpfs_targets`, `_mask_mount_targets` and
    `_tmpfs_copyup_seeds` and the interactions between them.
    """
    return [
        {
            "id": "empty",
            "why": "the no-mounts baseline; every list comes back empty.",
            "volumes": [],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "home-relative",
            "why": "`~` expands and the target half is passed through verbatim, "
                   "options included.",
            "volumes": ["~/work:/workspace:rw"],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "home-itself",
            "why": "the home directory is the boundary, and equality is inside "
                   "it — `real == home`, not just `startswith(home + '/')`.",
            "volumes": ["~:/host-home:ro"],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "env-var-set",
            "why": "`$VAR` expands through expandvars after expanduser.",
            "volumes": ["${APPLE_FIXTURE_DIR}/sub:/data:ro"],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "env-var-unset",
            "why": "an unset variable survives expandvars literally, and the "
                   "leftover `$` is what the skip branch keys on.",
            "volumes": ["$APPLE_FIXTURE_UNSET/foo:/cage:rw"],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "outside-home",
            "why": "an absolute path outside the operator's home is refused, "
                   "which is what keeps /etc and /var off the bind list.",
            "volumes": ["/etc:/cage:rw"],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "symlink-escapes-home",
            "why": "realpath, not the literal path, decides — a symlink in the "
                   "home directory pointing out of it is still outside.",
            "volumes": ["~/escape:/cage:rw"],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "missing-separator",
            "why": "no ':' means no cage-side path; skipped rather than guessed.",
            "volumes": ["~/work"],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "dotdot-normalized",
            "why": "realpath normalizes `..` before the containment check, so a "
                   "traversal cannot walk out of home and back in unnoticed.",
            "volumes": ["~/work/../work/sub:/data:rw"],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "dotdot-escapes-home",
            "why": "the same normalization catches a traversal that really does "
                   "leave home.",
            "volumes": ["~/work/../../outside:/data:rw"],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "non-persistent-bind",
            "why": "an `np` bind is accepted here and reports an EMPTY mask "
                   "source: its target is a tmpfs seeded from a read-only "
                   "lowerdir, so nothing written under it reaches the host.",
            "volumes": ["~/work:/workspace:rw,np"],
            "tmpfs": ["/workspace/.claude:rw,tmpcopyup"],
            "skip_targets": [],
        },
        {
            "id": "non-persistent-bind-bad-options",
            "why": "`np` is an overlay whose lower is read-only, so it cannot "
                   "compose with z/Z/U or a caller-supplied overlay dir. "
                   "`_user_volume_argv` validates before anything else and lets "
                   "the ValueError out — this is the one input that RAISES "
                   "rather than warning-and-skipping.",
            "volumes": ["~/work:/workspace:rw,np,z"],
            "tmpfs": [],
            "skip_targets": [],
        },
        {
            "id": "tmpfs-normalization",
            "why": "trailing slashes stripped, duplicates dropped after "
                   "normalization, options discarded (Apple's --tmpfs takes a "
                   "bare path), `/` and relative targets refused.",
            "volumes": [],
            "tmpfs": [
                "/tmp/:rw,noexec,nosuid,size=64M",
                "/tmp",
                "/var/log/",
                "/",
                "//",
                "relative/path:rw",
                "/a/b/",
            ],
            "skip_targets": [],
        },
        {
            "id": "copyup-seeded-from-bind",
            "why": "the headline copy-up shape: a mask nested under a persistent "
                   "bind seeds from the host directory it covers, mounted "
                   "read-only under /run/agentcage/masks/.",
            "volumes": ["~/project:/workspace:rw"],
            "tmpfs": [
                "/workspace/.claude:rw,tmpcopyup",
                "/workspace/nested:rw,nosuid,tmpcopyup",
            ],
            "skip_targets": [],
        },
        {
            "id": "copyup-index-is-positional",
            "why": "the `mask-<idx>` lower path is the index within "
                   "mask_copyup_entries, so an entry that yields no seed still "
                   "consumes its number — pinning that keeps the Rust side from "
                   "renumbering on a skip.",
            "volumes": ["~/project:/workspace:rw"],
            "tmpfs": [
                "/workspace/missing:rw,tmpcopyup",
                "/workspace/.claude:rw,tmpcopyup",
            ],
            "skip_targets": [],
        },
        {
            "id": "copyup-without-tmpcopyup",
            "why": "a mask that does not ask for copy-up is silently not seeded.",
            "volumes": ["~/project:/workspace:rw"],
            "tmpfs": ["/workspace/.claude:rw,nosuid"],
            "skip_targets": [],
        },
        {
            "id": "copyup-source-absent",
            "why": "a mask over a directory the project does not have is skipped "
                   "silently — seeding must never CREATE the host directory, or "
                   "a project without .claude/ grows one.",
            "volumes": ["~/project:/workspace:rw"],
            "tmpfs": ["/workspace/.absent:rw,tmpcopyup"],
            "skip_targets": [],
        },
        {
            "id": "copyup-source-escapes-bind",
            "why": "a repository containing `.evil -> ../../outside/secret` must "
                   "not turn the mask into a read-only window on a host path the "
                   "operator never shared; refused with a warning, mask comes up "
                   "empty.",
            "volumes": ["~/project:/workspace:rw"],
            "tmpfs": ["/workspace/.evil:rw,tmpcopyup"],
            "skip_targets": [],
        },
        {
            "id": "copyup-skip-target",
            "why": "#325's double-tmpfs avoidance: a target already covered by an "
                   "np tmpfs is seeded by cage-init from the np lowerdir, not by "
                   "a second mask mount.",
            "volumes": ["~/project:/workspace:rw"],
            "tmpfs": ["/workspace/.claude:rw,tmpcopyup"],
            "skip_targets": ["/workspace/.claude"],
        },
        {
            "id": "copyup-whole-bind",
            "why": "a mask covering the whole bind seeds from the bind source "
                   "itself — equality with the mount root is legitimate.",
            "volumes": ["~/project:/workspace:rw"],
            "tmpfs": ["/workspace:rw,tmpcopyup"],
            "skip_targets": [],
        },
        {
            "id": "copyup-unreachable-mount",
            "why": "a mask whose enclosing mount does not reach the host (no "
                   "matching bind at all) has nothing to seed from.",
            "volumes": [],
            "tmpfs": ["/plain/image/dir:rw,tmpcopyup"],
            "skip_targets": [],
        },
        {
            "id": "skipped-volume-is-not-a-mount",
            "why": "a volume `_user_volume_argv` refused never reaches the mask "
                   "logic, because `start()` feeds it the expanded argv rather "
                   "than the raw entries — so the tmpfs over it has no enclosing "
                   "host mount and nothing to seed from.",
            "volumes": ["/etc:/workspace:rw"],
            "tmpfs": ["/workspace/.claude:rw,tmpcopyup"],
            "skip_targets": [],
        },
    ]


def _corpus_volume_cases() -> list[dict]:
    """The same four helpers, over the corpus cages' real mount lists."""
    from agentcage.config import load_config

    cases: list[dict] = []
    for case in _CORPUS_CASES:
        cfg = load_config(str(_CORPUS / case / "input" / "cage.yaml"))
        volumes = list(cfg.container.volumes)
        # The corpus cages bind ${HOME}/workspace, which the sandbox tree
        # does not carry (and must not: the fixture's tree is its own
        # contract). Point them at a directory that exists instead, so the
        # copy-up branch is reached rather than short-circuited on isdir.
        volumes = [v.replace("${HOME}/workspace", "~/project") for v in volumes]
        cases.append({
            "id": f"corpus:{case}",
            "why": f"the mounts of golden corpus case `{case}`, which carries a "
                   f"quadlets/NOT-APPLICABLE.txt because this backend renders "
                   f"argv instead of units.",
            "volumes": volumes,
            "tmpfs": list(cfg.container.tmpfs),
            "skip_targets": [],
        })
    return cases


# ---------------------------------------------------------------------------
# Recorders
# ---------------------------------------------------------------------------

def _capture(fn, *args, **kwargs):
    """Run *fn*, returning ``(result, warning_lines)``.

    Every skip in this backend is a ``click.echo(..., err=True)``, so the
    warnings are as much a part of the contract as the return value — they
    are the only signal an operator gets that a mount was dropped.
    """
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        result = fn(*args, **kwargs)
    return result, [line for line in stderr.getvalue().splitlines() if line]


def _record_volumes(cases: list[dict], scrub: Scrubber) -> list[dict]:
    from agentcage.backends.apple_container import AppleContainerBackend as B

    out: list[dict] = []
    for case in cases:
        volumes = list(case["volumes"])
        tmpfs = list(case["tmpfs"])
        skip = set(case["skip_targets"])

        try:
            argv, argv_warnings = _capture(B._user_volume_argv, volumes)
        except ValueError as exc:
            # `validate_non_persistent_volume` is the only thing in this
            # backend's generation half that raises rather than warning.
            out.append(scrub.value({
                **case,
                "skip_targets": sorted(skip),
                "expected": {
                    "user_volume_argv": {
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                },
            }))
            continue
        targets, target_warnings = _capture(B._tmpfs_targets, tmpfs)
        # `start()` feeds the mask logic the EXPANDED entries — the output
        # of `_user_volume_argv`, not the raw `container.volumes`
        # (apple_container.py:1805). That matters twice over: `~` and
        # `$VAR` are already gone, so `os.path.isdir` sees a real path;
        # and an entry `_user_volume_argv` refused is not a mount at all,
        # so nothing nests under it. Recording it any other way would pin
        # a wiring the backend does not have.
        mask_targets, _ = _capture(B._mask_mount_targets, list(argv))
        seeds, seed_warnings = _capture(B._tmpfs_copyup_seeds, tmpfs, list(argv), skip)

        out.append(scrub.value({
            **case,
            "skip_targets": sorted(skip),
            "expected": {
                "user_volume_argv": {
                    "argv": list(argv),
                    "warnings": argv_warnings,
                },
                "tmpfs_targets": {
                    "targets": list(targets),
                    "warnings": target_warnings,
                },
                "mask_mount_targets": [list(t) for t in mask_targets],
                "tmpfs_copyup_seeds": {
                    "seeds": [list(s) for s in seeds],
                    "warnings": seed_warnings,
                },
            },
        }))
    return out


def _record_image(scrub: Scrubber, work: Path) -> dict:
    """Image naming and the egress build argv.

    The content hash itself belongs to `tests/fixtures/egress_hash.json`;
    what this records is the *wiring* — that the tag is
    ``<repo>:<version>-<hash>``, that the hash comes from the build
    context rather than from the version, and that the build argv names
    the Containerfile and the context in the order Apple's CLI is handed
    them.
    """
    from agentcage import egress_hash
    from agentcage.backends.apple_container import (
        _EGRESS_CONTAINERFILE_REL,
        _EGRESS_IMAGE_REPO,
        _egress_data_dir,
        _egress_image_name,
    )

    data_dir = _egress_data_dir()
    real_hash = egress_hash.egress_content_hash(data_dir)
    real_name = _egress_image_name()

    # A throwaway build context, to show the hash is a function of the
    # COPY sources and nothing else: same Containerfile, one byte changed
    # in a copied file, different tag.
    ctx = work / "ctx"
    (ctx / "containers").mkdir(parents=True, exist_ok=True)
    (ctx / "containers" / "Containerfile.egress").write_text(
        "FROM scratch\n"
        "COPY containers/seed.sh /seed.sh\n"
        "RUN echo not-a-copy-source\n"
    )
    (ctx / "containers" / "seed.sh").write_text("#!/bin/sh\nexit 0\n")
    before = _egress_image_name(ctx)
    (ctx / "containers" / "seed.sh").write_text("#!/bin/sh\nexit 1\n")
    after = _egress_image_name(ctx)
    assert before != after, "a changed COPY source must change the tag"

    # `_build_egress_image_if_missing`'s argv, in its four shapes. Built
    # here rather than called, because calling it shells out to
    # `container`(1) — which is PR E5's half and needs a Mac.
    #
    # The build context is `{{CONTEXT}}`, not a real path: the Python's is
    # the installed package's own `data/` directory, and a single Rust
    # binary has no such directory — it materializes the embedded tree into
    # a cache dir instead (RUST-PORT-PLAN.md section 2.1). The argv SHAPE is
    # the contract; where the context lives is not.
    def argv(no_cache: bool, pull: bool) -> list[str]:
        out = ["build", "-t", real_name, "-f",
               f"{_SCRUB_CONTEXT}/{_EGRESS_CONTAINERFILE_REL}"]
        if no_cache:
            out.append("--no-cache")
        if pull:
            out.append("--pull")
        out.append(_SCRUB_CONTEXT)
        return out

    return {
        "repo": _EGRESS_IMAGE_REPO,
        "containerfile_rel": _EGRESS_CONTAINERFILE_REL,
        "build_context": _SCRUB_CONTEXT,
        "version": _SCRUB_VERSION,
        "content_hash": real_hash,
        "image_name": scrub.text(real_name),
        "synthetic_context": {
            "why": "one Containerfile, one COPY source, one byte changed — the "
                   "tag moves. A version-only tag would not, which is how the "
                   "#186 proxy-log fix failed to reach hosts that already held "
                   "`agentcage-egress:0.32.0`.",
            "containerfile": "FROM scratch\nCOPY containers/seed.sh /seed.sh\n"
                             "RUN echo not-a-copy-source\n",
            "copy_source_path": "containers/seed.sh",
            "before": {"body": "#!/bin/sh\nexit 0\n", "image_name": scrub.text(before)},
            "after": {"body": "#!/bin/sh\nexit 1\n", "image_name": scrub.text(after)},
        },
        "build_argv": {
            "plain": [scrub.text(a) for a in argv(False, False)],
            "no_cache": [scrub.text(a) for a in argv(True, False)],
            "pull": [scrub.text(a) for a in argv(False, True)],
            "no_cache_and_pull": [scrub.text(a) for a in argv(True, True)],
        },
        "data_dir_is_the_package": scrub.text(
            str(data_dir.relative_to(_ROOT))
        ),
    }


def _record_state_paths(scrub: Scrubber) -> dict:
    """The per-cage state layout, and the XDG wart it is built on.

    ``_state_dir`` is ``expanduser("~/.config/agentcage/apple-container")``
    with no ``XDG_CONFIG_HOME`` lookup.  The sandbox deliberately puts the
    XDG roots somewhere else, so this fixture shows an apple path that does
    NOT follow them next to a container-backend path that does.
    """
    from agentcage import state
    from agentcage.backends.apple_container import AppleContainerBackend

    backend = AppleContainerBackend()
    name = "demo"
    return scrub.value({
        "why": "the apple-container state root expands `~` directly and ignores "
               "XDG_CONFIG_HOME (RUST-PORT-PLAN.md section 2.7). An XDG-only "
               "sandbox does not redirect it — which makes it a testing hazard, "
               "not just a portability wart.",
        "env": {
            "HOME": os.environ["HOME"],
            "XDG_CONFIG_HOME": os.environ["XDG_CONFIG_HOME"],
            "XDG_DATA_HOME": os.environ["XDG_DATA_HOME"],
        },
        "cage": name,
        "apple": {
            "state_dir": str(backend._state_dir(name)),
            "logs_dir": str(backend.logs_dir(name)),
            "egress_config_dir": str(backend.egress_config_dir(name)),
            "certs_dir": str(backend.certs_dir(name)),
            "public_certs_dir": str(backend.public_certs_dir(name)),
            "secrets_dir": str(backend.secrets_dir(name)),
            "mask_state_path": str(backend._mask_state_path(name)),
        },
        "contrast": {
            "why": "the container backend's secrets staging, for comparison: a "
                   "tmpfs under XDG_RUNTIME_DIR. The apple one above is "
                   "PERSISTENT DISK, because macOS has neither. Deliberate, and "
                   "easy to mistake for a bug.",
            "container_runtime_secrets_dir": str(state.runtime_secrets_dir(name)),
            "deployment_dir": str(state.deployment_dir(name)),
        },
    })


def _egress_config_extra_cases() -> list[tuple[str, str, str]]:
    """Extra `(case, cage, yaml)` inputs the corpus does not cover.

    The corpus's five apple cages all carry the same two allowlisted
    domains, which never reaches the dnsmasq template's `{% else %}` branch
    and never exercises the effective-allowlist widening. These do.
    """
    base = (
        "container:\n"
        "  image: docker.io/library/node:22-slim\n"
        "  command:\n"
        "  - node\n"
        "  - /app/agent.js\n"
        "isolation: apple-container\n"
    )
    return [
        (
            "domains-none",
            "apple-domains-none",
            f"name: apple-domains-none\n{base}",
        ),
        (
            "domains-passthrough",
            "apple-passthrough",
            f"name: apple-passthrough\n{base}"
            "domains:\n"
            "  allow:\n"
            "  - api.example.com\n"
            "  passthrough:\n"
            "  - tunnel.example.net\n"
            "dns_servers:\n"
            "- 192.0.2.53\n"
            "- 192.0.2.54\n",
        ),
        (
            "agents-decider",
            "apple-agents-decider",
            f"name: apple-agents-decider\n{base}"
            "domains:\n"
            "  allow:\n"
            "  - api.example.com\n"
            "dns_servers:\n"
            "- 192.0.2.53\n"
            "agents:\n"
            "  decider:\n"
            "    enable: true\n"
            "    provider: anthropic\n"
            "    model: claude-fake-1\n"
            "    api_key: systemd-creds:FAKE_DECIDER_KEY\n"
            "    base_url: ''\n",
        ),
    ]


def _record_egress_config(scrub: Scrubber, work: Path) -> tuple[dict, dict[str, str]]:
    """`_render_egress_config`, over every apple case in the golden corpus.

    Three files land in the per-cage egress-config dir and are bind-mounted
    read-only into the egress microVM:

      * ``proxy-config.yaml``  — copied from `state.save_proxy_config`, so
        the on-disk shape is identical to the container/vm backends';
      * ``dnsmasq.conf``       — rendered from the EFFECTIVE DNS allowlist
        (allow + passthrough + relay upstreams + the agents decider host),
        which is `quadlets._effective_dns_allowlist`, the same single source
        of truth the container backend uses;
      * ``dns-allowlist.conf`` — copied from `state.save_dns_allowlist`.

    The pre-create fallback (no stored cage.yaml yet) is recorded too: it
    is the branch that writes a minimal proxy-config and an inline
    allowlist, and it has no test anywhere else in the tree.

    Returns ``(manifest, files)`` — the rendered bytes go to real files
    under ``egress-config/<case>/`` rather than into a JSON blob, because
    a dnsmasq.conf is 3 KB of mostly comment and seven copies of it inside
    one document is not a reviewable diff.
    """
    from agentcage import state
    from agentcage.backends.apple_container import AppleContainerBackend
    from agentcage.config import load_config

    backend = AppleContainerBackend()
    records: list[dict] = []
    files: dict[str, str] = {}

    def record(case: str, cage: str, why: str, stored: bool,
               warnings: list[str], source: Path) -> None:
        # The input travels with the output. A consumer needs the
        # cage.yaml to reproduce the render, and three of these configs
        # are not in the golden corpus at all — pointing at a path in
        # another fixture tree would make this one unreadable alone.
        files[f"egress-config/{case}/input/cage.yaml"] = scrub.text(source.read_text())
        directory = backend.egress_config_dir(cage)
        names: list[str] = []
        for path in sorted(directory.iterdir()):
            if not path.is_file():
                continue
            files[f"egress-config/{case}/{path.name}"] = scrub.text(path.read_text())
            names.append(path.name)
        records.append({
            "case": case,
            "cage": cage,
            "stored": stored,
            "why": why,
            "input": f"egress-config/{case}/input/cage.yaml",
            "warnings": [scrub.text(w) for w in warnings],
            "files": names,
        })

    def render_stored(case: str, cage: str, src: Path, why: str) -> None:
        state.save_deployment(cage, str(src))
        cfg = state.load_deployment_config(cage)
        _, warnings = _capture(backend._render_egress_config, cfg, cage)
        record(case, cage, why, True, warnings, src)

    for case in _CORPUS_CASES:
        render_stored(
            case, case, _CORPUS / case / "input" / "cage.yaml",
            f"golden corpus case `{case}` — the one that carries a "
            f"quadlets/NOT-APPLICABLE.txt, now with the artifacts this "
            f"backend actually renders in its place.",
        )

    for case, cage, yaml_text in _egress_config_extra_cases():
        src = work / f"{cage}.yaml"
        src.write_text(yaml_text)
        render_stored(
            case, cage, src,
            "not in the golden corpus: widens the effective DNS allowlist "
            "past `domains.allow`, or empties it entirely so the dnsmasq "
            "template takes its no-upstreams branch.",
        )

    # The pre-create branch: a config that was never saved, so
    # `state.save_proxy_config` raises FileNotFoundError and both fallbacks
    # fire. Uses the plainest corpus case so the diff against its stored
    # counterpart above is exactly the fallback's effect.
    src = _CORPUS / "backend-apple-container" / "input" / "cage.yaml"
    cfg = load_config(str(src))
    _, warnings = _capture(backend._render_egress_config, cfg, "unsaved-cage")
    record(
        "pre-create-fallback", "unsaved-cage",
        "no cage.yaml on disk yet: `save_proxy_config` and "
        "`save_dns_allowlist` both raise FileNotFoundError and the in-line "
        "fallbacks render a minimal proxy-config plus an allowlist derived "
        "from the effective DNS list. Note what the minimal proxy-config "
        "does NOT carry: no `agentcage_version`, and only `domains.allow` "
        "— not the passthrough list, not the inspectors, not the secret "
        "injection rules.",
        False, warnings, src,
    )

    # A second fallback shape, and the only way to reach the in-line
    # allowlist's own ["1.1.1.1", "8.8.8.8"] default: an EMPTY
    # `dns_servers`. `load_config` never produces one — line 1412 is
    # `raw.get("dns_servers") or _host_dns_servers()`, so an explicit `[]`
    # is falsy and auto-detection wins — so this needs a Config built by
    # hand, which is what the backend's own tests do.
    cfg = load_config(str(src))
    cfg.name = "empty-dns-servers"
    cfg.dns_servers = []
    _, warnings = _capture(backend._render_egress_config, cfg, "empty-dns-servers")
    record(
        "pre-create-fallback-empty-dns-servers", "empty-dns-servers",
        "the in-line allowlist fallback's own 1.1.1.1/8.8.8.8 default, "
        "which needs BOTH no stored cage.yaml and an empty `dns_servers`. "
        "`load_config` cannot produce the latter (an explicit `[]` is "
        "falsy and auto-detection wins), so this is reachable only from a "
        "hand-built Config — recorded so a port knows the branch exists "
        "and what it does, rather than dropping it as dead. The two files "
        "agree on 1.1.1.1/8.8.8.8 by coincidence rather than by "
        "construction: dns-allowlist.conf gets the backend's literal pair, "
        "dnsmasq.conf gets `wrapper._DEFAULT_DNS_SERVERS`. A port that "
        "changes one and not the other would split them. The recorded "
        "input is the stored case's cage.yaml; `dns_servers` is emptied on "
        "the loaded Config afterwards, since no cage.yaml can express it.",
        False, warnings, src,
    )

    manifest = {
        "_comment": "`_render_egress_config` output for every apple-container "
                    "case in the golden corpus, plus three configs the corpus "
                    "does not carry and the two pre-create fallback shapes. The "
                    "bytes are in egress-config/<case>/.",
        "cases": records,
    }
    return manifest, files


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def _render(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def _generate(work: Path) -> dict[str, str]:
    """Produce every fixture document, as ``{filename: text}``."""
    root, env = _build_sandbox(work)
    _install_determinism_patches()

    version = (_ROOT / "VERSION").read_text().strip()
    scrub = Scrubber(root, version)

    from agentcage.backends.apple_container import _agentcage_version

    if _agentcage_version() != version:
        raise SystemExit(
            f"the installed agentcage reports {_agentcage_version()!r} but "
            f"VERSION says {version!r}; run this under `uv run` in a synced "
            f"checkout so the image tag is the one a user would get"
        )

    tree = {
        "why": "the filesystem every volume/tmpfs case below is resolved "
               "against. Paths are relative to the sandbox root; a consumer "
               "materializes it in a temporary directory and points HOME at "
               "`home/`.",
        "root": _SCRUB_ROOT,
        "home": f"{_SCRUB_ROOT}/home",
        "dirs": list(_TREE_DIRS),
        "symlinks": dict(_TREE_SYMLINKS),
        "env": {
            key: scrub.text(value)
            for key, value in sorted(env.items())
            if key.startswith(("HOME", "APPLE_FIXTURE"))
        },
        "unset_env": ["APPLE_FIXTURE_UNSET"],
    }

    documents = {
        "image.json": {
            "_comment": "Image naming and the egress build argv, as "
                        "`backends/apple_container.py` produces them. The "
                        "content hash is NOT scrubbed: it is the frozen "
                        "cross-language contract pinned by "
                        "tests/fixtures/egress_hash.json.",
            **_record_image(scrub, work),
        },
        "state-paths.json": _record_state_paths(scrub),
        "volumes.json": {
            "_comment": "Everything the apple backend derives from a cage's "
                        "`container.volumes` and `container.tmpfs`. Inputs are "
                        "curated; expectations are computed by running the real "
                        "Python with platform.system() patched to Darwin.",
            "tree": tree,
            "cases": _record_volumes(_volume_cases() + _corpus_volume_cases(), scrub),
        },
    }

    egress_manifest, egress_files = _record_egress_config(scrub, work)
    documents["egress-config.json"] = egress_manifest

    rendered = {name: _render(doc) for name, doc in documents.items()}
    rendered.update(egress_files)
    for text in rendered.values():
        _assert_no_leaks(text, root)
    return rendered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero if any fixture is out of date")
    args = parser.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="agentcage-apple-fixtures-"))
    try:
        rendered = _generate(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    _OUT.mkdir(parents=True, exist_ok=True)
    stale: list[str] = []
    for name, text in sorted(rendered.items()):
        path = _OUT / name
        if args.check:
            current = path.read_text() if path.exists() else ""
            fresh = current == text
            if not fresh:
                stale.append(name)
            print(f"{'ok   ' if fresh else 'STALE'} {name}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            print(f"wrote {path.relative_to(_ROOT)}")

    # A case that was renamed or dropped leaves its files behind, and a
    # stale file nothing regenerates is worse than a missing one: the Rust
    # side would keep asserting against a recording of code that no longer
    # exists. `--check` reports them; a write removes them.
    committed = {
        str(path.relative_to(_OUT))
        for path in _OUT.rglob("*")
        if path.is_file() and path.name != "README.md"
    }
    for orphan in sorted(committed - set(rendered)):
        if args.check:
            stale.append(orphan)
            print(f"EXTRA {orphan}")
        else:
            (_OUT / orphan).unlink()
            print(f"removed {orphan}")
    for directory in sorted(
        (d for d in _OUT.rglob("*") if d.is_dir()), reverse=True
    ):
        if not args.check and not any(directory.iterdir()):
            directory.rmdir()

    if stale:
        print("\nOut of date. Regenerate with:\n"
              "    uv run python scripts/gen-apple-container-fixtures.py\n"
              "and review the diff — this backend has no CI on real hardware, "
              "so the fixture is the only thing watching it.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
