"""Content hash over the agentcage-egress image's build inputs.

This is a **cross-language contract**, which is the only reason it lives in
its own module instead of inside the apple-container backend where it grew.

Why the hash exists at all (#312): the shared egress image used to be
tagged ``localhost/agentcage-egress:<agentcage version>`` and
``_build_egress_image_if_missing()`` skips the build whenever that exact
tag is already present locally. Nothing about the image's *contents* took
part in that decision, so a security fix landing in ``supervisor-egress.sh``
or the mitmproxy addon between releases silently never reached a host that
already held the tag. Measured on a real Mac: with a ``0.32.0`` image built
before the #186 proxy-log hardening, the running egress VM still had the
pre-fix supervisor and a world-readable ``audit.jsonl`` (0644), while
``cage create`` cheerfully printed "already present; skipping rebuild".
Same version, same command, opposite security posture — decided purely by
whether a stale tag happened to be there. The tag is now
``localhost/agentcage-egress:<version>-<12 hex>``, so a changed input
yields a tag the host cannot already have, the "already present?" probe
misses, and the rebuild happens with no flag.

Why it is a *contract*: the Rust port (RUST-PORT-PLAN §2.1) keeps the
egress image Python but moves the host CLI to Rust, where the build context
is extracted from bytes embedded in the binary. The Rust implementation
must reproduce this digest **byte-exactly**. If it does not, every Mac
rebuilds its egress image once on upgrade and then drifts permanently from
the Python-computed tag — two parallel tag lineages for identical content,
and the "already present" skip stops meaning anything across the boundary.

The wire format is therefore frozen. SHA256 over the sorted build inputs,
each contributing::

    relpath (utf-8) || 0x00 || len(body) as 8-byte big-endian || body

truncated to the first ``TAG_HASH_LEN`` hex characters. Sorting is by POSIX
relative path, so the result never depends on filesystem iteration order,
and the path is hashed alongside the bytes so a pure rename still moves the
digest. The length prefix means no path+content concatenation can be
re-partitioned into a different input set with the same hash.

``tests/test_egress_hash.py`` pins the digest of the tree as it stands
against ``tests/fixtures/egress_hash.json``, which is what a future Rust
test should check itself against.

Constraints this module must keep, so both a Rust test and a non-macOS
caller can use it:

* **stdlib only** — no third-party imports, not even ``click``;
* **no agentcage imports** — in particular nothing from
  ``agentcage.backends``, which pulls in the whole apple-container stack.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from pathlib import Path, PurePosixPath


__all__ = [
    "CONTAINERFILE_REL",
    "COPY_RE",
    "HASH_EXCLUDE_DIRS",
    "HASH_EXCLUDE_SUFFIXES",
    "TAG_HASH_LEN",
    "UNKNOWN_HASH",
    "containerfile_logical_lines",
    "egress_build_inputs",
    "egress_content_hash",
    "egress_copy_sources",
    "egress_data_dir",
]


# Truncated sha256 length for the tag suffix. 12 hex chars = 48 bits;
# collisions across the handful of egress builds a host ever sees are not
# a practical concern, and a short tag keeps `container images` readable.
TAG_HASH_LEN = 12

# Containerfile path relative to the build context (src/agentcage/data).
CONTAINERFILE_REL = "containers/Containerfile.egress"

# What an empty/absent build context hashes to. Callers embed this in the
# image tag rather than failing, so the build path can report the missing
# Containerfile with its own actionable error.
UNKNOWN_HASH = "unknown"

# `COPY [--flag=…] <src>… <dest>`. Only the shell form is matched; the
# egress Containerfile does not use the JSON-array form (a JSON COPY would
# simply contribute no sources, and the Containerfile's own bytes are
# always hashed, so the tag still changes whenever it is edited).
COPY_RE = re.compile(r"^COPY\s+(?P<rest>.+)$", re.IGNORECASE)

# Build-context noise that must never reach the hash: bytecode caches are
# interpreter-dependent, so hashing them would make the tag unstable
# across Python versions for byte-identical sources. A Rust port has no
# __pycache__ of its own, but the Python build context it extracts may
# well acquire one, so the exclusion has to be part of the contract.
HASH_EXCLUDE_DIRS = frozenset({"__pycache__"})
HASH_EXCLUDE_SUFFIXES = (".pyc", ".pyo")


def egress_data_dir() -> Path:
    """Build context for the egress image (``src/agentcage/data``).

    Resolved relative to this file so the build works regardless of cwd
    (tests, agentcage invoked from a sub-dir, etc.).
    """
    return Path(__file__).resolve().parent / "data"


def containerfile_logical_lines(text: str):
    """Yield Containerfile instructions with backslash continuations joined.

    Comment-only lines are dropped. Good enough to find COPY sources; this
    is deliberately not a general Containerfile parser.
    """
    buf = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        buf += stripped
        if buf:
            yield buf
        buf = ""
    if buf:
        yield buf


def egress_copy_sources(containerfile_text: str) -> list[str]:
    """Source paths named by the COPY directives of the egress Containerfile.

    Deriving the list from the Containerfile (rather than hardcoding it)
    means a new `COPY proxy/<something-new>` joins the content hash
    automatically, instead of silently falling out of the rebuild decision
    the way a hand-maintained list eventually would.
    """
    sources: list[str] = []
    for line in containerfile_logical_lines(containerfile_text):
        match = COPY_RE.match(line)
        if match is None:
            continue
        try:
            parts = shlex.split(match.group("rest"))
        except ValueError:
            continue
        # Drop `--chown=`/`--from=`-style flags; the final token is the
        # destination inside the image, everything before it is a source.
        parts = [p for p in parts if not p.startswith("--")]
        if len(parts) < 2:
            continue
        sources.extend(parts[:-1])
    return sources


def egress_build_inputs(data_dir: Path | None = None) -> list[tuple[str, Path]]:
    """Every file baked into the egress image, as sorted (relpath, path) pairs.

    The Containerfile itself plus the transitive contents of each COPY
    source (directories are walked). Returns ``[]`` when the Containerfile
    is missing — the build path reports that with an actionable error.
    """
    root = (data_dir or egress_data_dir()).resolve()
    containerfile = root / CONTAINERFILE_REL
    if not containerfile.is_file():
        return []

    inputs: dict[str, Path] = {CONTAINERFILE_REL: containerfile}

    def _add(path: Path) -> None:
        if not path.is_file():
            return
        if path.suffix in HASH_EXCLUDE_SUFFIXES:
            return
        try:
            rel = path.relative_to(root)
        except ValueError:
            return  # outside the build context; `container build` can't COPY it
        if HASH_EXCLUDE_DIRS.intersection(rel.parts):
            return
        inputs[rel.as_posix()] = path

    for src in egress_copy_sources(containerfile.read_text(errors="replace")):
        parts = PurePosixPath(src.strip("/")).parts
        if not parts or ".." in parts:
            continue
        target = root.joinpath(*parts)
        if target.is_dir():
            for child in target.rglob("*"):
                _add(child)
        else:
            # A missing source contributes nothing on purpose: the build
            # itself fails loudly on it and there are no bytes to hash.
            _add(target)

    return sorted(inputs.items())


def egress_content_hash(data_dir: Path | None = None) -> str:
    """Short stable digest over the egress image's build inputs.

    Hashes the sorted (relative path, content) pairs so a rename changes
    the digest even when the bytes do not, and so the result does not
    depend on filesystem iteration order.

    The byte layout below is the cross-language contract — see the module
    docstring. Do not "clean it up".
    """
    inputs = egress_build_inputs(data_dir)
    if not inputs:
        return UNKNOWN_HASH
    digest = hashlib.sha256()
    for rel, path in inputs:
        try:
            body = path.read_bytes()
        except OSError:
            body = b""
        digest.update(rel.encode())
        digest.update(b"\0")
        # Length-prefix the body so no path+content concatenation can be
        # re-partitioned into a different input set with the same hash.
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return digest.hexdigest()[:TAG_HASH_LEN]
