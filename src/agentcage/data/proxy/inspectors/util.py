"""Shared utilities for agentcage inspectors."""

from __future__ import annotations

import importlib.util
import math
import os
from collections import Counter

from inspectors.base import Inspector


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 – 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


_DEFAULT_ALLOWED_DIRS = ["/etc/agentcage/inspectors"]


def load_inspector_from_file(
    path: str,
    allowed_dirs: list[str] | None = None,
) -> Inspector:
    """Import a Python file and return the first Inspector subclass found.

    For security, the path must resolve to a location under one of the
    ``allowed_dirs``.  Defaults to ``/etc/agentcage/inspectors``.
    Override via the ``AGENTCAGE_INSPECTOR_DIRS`` env var
    (colon-separated list of directories).
    """
    if allowed_dirs is None:
        env_dirs = os.environ.get("AGENTCAGE_INSPECTOR_DIRS")
        if env_dirs:
            allowed_dirs = [d for d in env_dirs.split(":") if d]
        else:
            allowed_dirs = list(_DEFAULT_ALLOWED_DIRS)

    real_path = os.path.realpath(path)
    if not any(
        real_path.startswith(os.path.realpath(d) + os.sep)
        or real_path == os.path.realpath(d)
        for d in allowed_dirs
    ):
        raise ImportError(
            f"custom inspector path {path!r} (resolved: {real_path!r}) "
            f"is outside allowed directories: {allowed_dirs}"
        )

    spec = importlib.util.spec_from_file_location("_custom_inspector", real_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for attr in dir(mod):
        obj = getattr(mod, attr)
        if (
            isinstance(obj, type)
            and issubclass(obj, Inspector)
            and obj is not Inspector
        ):
            return obj()
    raise ImportError(f"no Inspector subclass found in {path}")
