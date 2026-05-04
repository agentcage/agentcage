"""Protocol relays — non-HTTP secret injection.

mitmproxy's ``secret_injection`` only works for credentials that travel
on the wire over HTTP(S). Some protocols (IMAP, SMTP) are stateful,
binary, and use their own authentication exchanges — and yet from a
trust standpoint we want the same property: the cage holds no real
credentials, the proxy holds them, the cage talks to a localhost
listener and the relay does the upstream auth on its behalf.

Each relay is an asyncio TCP listener housed in the proxy container.
On client connect, it opens an authenticated upstream connection,
proxies bytes back to the client, and applies a per-protocol policy
(read-only, folder allowlist, etc.) at command granularity.
"""

from __future__ import annotations

from typing import Type

from relays.imap import ImapRelay

_REGISTRY: dict[str, Type] = {
    "imap": ImapRelay,
}


def register(name: str, cls: Type) -> None:
    _REGISTRY[name] = cls


def get(name: str) -> Type:
    if name not in _REGISTRY:
        valid = ", ".join(sorted(_REGISTRY))
        raise KeyError(
            f"unknown relay type '{name}'. Registered: {valid or '(none)'}"
        )
    return _REGISTRY[name]


def known() -> list[str]:
    return sorted(_REGISTRY)
