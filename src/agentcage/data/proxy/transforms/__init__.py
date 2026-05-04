"""Secret-injection transforms — produce a substitution value at request
time instead of using a static ``real_value``.

A transform is a callable object with two requirements:

1. ``__init__(self, secret: str, config: dict)`` — receives the raw
   credential (loaded from the proxy container's environment by the
   injector) and the per-rule ``transform_config`` block.
2. ``get_value(self) -> str`` — called every time a placeholder is about
   to be substituted on an outbound request to an authorized domain.
   May cache, rate-limit, and emit audit events internally.

Transforms exist so that long-lived high-privilege credentials (SA
private keys, refresh tokens) never leave the proxy container — only
short-lived derived values (access tokens) ever land on the wire.
"""

from __future__ import annotations

from typing import Type

from transforms.google_jwt_bearer import GoogleJwtBearer

_REGISTRY: dict[str, Type] = {
    "google-jwt-bearer": GoogleJwtBearer,
}


def register(name: str, cls: Type) -> None:
    """Register a transform class under a config name."""
    _REGISTRY[name] = cls


def get(name: str) -> Type:
    """Look up a transform class by its config name.

    Raises KeyError with the list of registered names if unknown.
    """
    if name not in _REGISTRY:
        valid = ", ".join(sorted(_REGISTRY))
        raise KeyError(
            f"unknown transform '{name}'. Registered: {valid or '(none)'}"
        )
    return _REGISTRY[name]


def known() -> list[str]:
    """Return the sorted list of registered transform names."""
    return sorted(_REGISTRY)
