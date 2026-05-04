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

Concrete relay classes (``relays.imap.ImapRelay`` etc.) live in the
proxy container's sys.path, not the CLI's. We deliberately avoid
importing them at package-init time so the CLI can import the shared
validation helpers in ``_validate`` without dragging in proxy-only
modules.
"""

from __future__ import annotations

from typing import Type

# Extra registrations can be made by callers via ``register()``.
_REGISTRY: dict[str, Type] = {}


def register(name: str, cls: Type) -> None:
    _REGISTRY[name] = cls


_BUILTINS = frozenset({"imap", "smtp"})


def _lazy_load(name: str) -> Type:
    """Resolve a built-in relay class on first ``get()`` call.

    Imports happen here (not at package init) so the CLI can import
    ``relays._validate`` without requiring the proxy's sys.path layout.
    """
    if name == "imap":
        from relays.imap import ImapRelay
        return ImapRelay
    if name == "smtp":
        from relays.smtp import SmtpRelay
        return SmtpRelay
    raise KeyError(name)


def get(name: str) -> Type:
    cls = _REGISTRY.get(name)
    if cls is not None:
        return cls
    try:
        cls = _lazy_load(name)
    except KeyError:
        valid = ", ".join(sorted(set(_REGISTRY) | _BUILTINS))
        raise KeyError(
            f"unknown relay type '{name}'. Registered: {valid or '(none)'}"
        )
    _REGISTRY[name] = cls
    return cls


def known() -> list[str]:
    """Return the union of explicitly-registered and built-in relay
    types. The built-ins are listed without forcing their import."""
    return sorted(set(_REGISTRY) | _BUILTINS)
