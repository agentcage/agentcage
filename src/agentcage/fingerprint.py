"""Stable deployment fingerprints used by ``cage update`` no-op detection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import yaml


FINGERPRINT_VERSION = 1


def stable_json(value: Any) -> str:
    """Serialize JSON-compatible *value* deterministically."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _sha256(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()


def normalize_cage_yaml(cage_yaml: str | Mapping[str, Any]) -> str:
    """Return a canonical JSON form of a cage configuration.

    Parsing YAML before serializing means comments, whitespace, and mapping-key
    order do not affect the result. Sequence order remains significant because
    it can affect generated container arguments and policy evaluation.
    """
    if isinstance(cage_yaml, str):
        value = yaml.safe_load(cage_yaml) or {}
    else:
        value = dict(cage_yaml)
    return stable_json(value)


def compute_fingerprint(
    cage_yaml: str | Mapping[str, Any],
    *,
    resolved_config: Mapping[str, Any],
    units: Mapping[str, str],
    image_digests: Mapping[str, str],
    scaffold_version: str,
) -> dict[str, Any]:
    """Compute a versioned fingerprint from resolved deployment inputs.

    The component hashes make ``fingerprint.json`` useful for diagnostics while
    the top-level hash provides a single stable comparison value.
    """
    normalized_yaml = normalize_cage_yaml(cage_yaml)
    components = {
        "cage_yaml": _sha256(normalized_yaml),
        "resolved_config": _sha256(stable_json(dict(resolved_config))),
        "units": _sha256(stable_json(dict(units))),
        "image_digests": _sha256(stable_json(dict(image_digests))),
        "scaffold_version": _sha256(scaffold_version),
    }
    payload = {"version": FINGERPRINT_VERSION, "components": components}
    return {
        **payload,
        "fingerprint": _sha256(stable_json(payload)),
    }


def fingerprint_matches(stored: object, current: Mapping[str, Any]) -> bool:
    """Return whether two supported, well-formed fingerprints match."""
    return (
        isinstance(stored, dict)
        and stored.get("version") == FINGERPRINT_VERSION
        and stored.get("fingerprint") == current.get("fingerprint")
    )


_STATE_ARTIFACTS = frozenset({
    "cage.yaml",
    "metadata.json",
    "fingerprint.json",
    "proxy-config.yaml",
    "dns-allowlist.conf",
    "pending_secrets.json",
    "cage-env",
    "creds",
})


def scaffold_context_version(state_dir: Path, containerfile: str) -> str:
    """Hash the frozen build context staged for an existing scaffold cage.

    VM updates copy this context into the guest before rebuilding, while the
    other backends build it directly. Derived deployment state is excluded so
    writing a fingerprint cannot invalidate itself.
    """
    if not containerfile:
        return ""

    root = state_dir.resolve()
    containerfile_path = Path(containerfile)
    if containerfile_path.is_absolute():
        root = containerfile_path.resolve().parent
    if not root.is_dir():
        return "missing"

    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in _STATE_ARTIFACTS:
            continue
        if not path.is_file():
            continue
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
