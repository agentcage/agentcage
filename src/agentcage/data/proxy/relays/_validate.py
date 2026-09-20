"""Structural validation for ``protocol_relays`` entries.

Lives under ``data/proxy/relays/`` so both sides of the trust boundary
import the same code: the CLI imports it as
``agentcage.data.proxy.relays._validate``; the proxy container imports
it as ``relays._validate`` (the proxy ships in its own image without
the CLI package on the path).

This module is intentionally dependency-free apart from stdlib so it
loads cleanly in the proxy environment. Source-scheme validation is
left to the caller as an optional callable hook because the canonical
validator (``agentcage.secret_resolver.validate_source``) is not
available inside the proxy container.
"""

from __future__ import annotations

from typing import Callable, Optional

KNOWN_RELAY_TYPES = frozenset({"imap", "smtp"})

# IMAP write policy. "organise" permits filing and flagging but
# refuses anything that destroys mail — see relays/imap.py.
_WRITE_MODES = frozenset({"none", "organise", "full"})


def validate_relay_type(name: str) -> None:
    if name not in KNOWN_RELAY_TYPES:
        valid = ", ".join(sorted(KNOWN_RELAY_TYPES))
        raise ValueError(
            f"unknown protocol_relays type: '{name}'. Valid: {valid}"
        )


def validate_relay_entry(
    entry: dict,
    source_validator: Optional[Callable[[str], None]] = None,
) -> None:
    """Validate one ``protocol_relays`` YAML entry.

    Raises ``ValueError`` on any structural problem. ``source_validator``
    is called for ``auth.user_source`` and ``auth.password_source`` if
    provided; pass ``None`` from contexts (like the proxy container)
    where the canonical validator is not importable.
    """
    if not isinstance(entry, dict):
        raise ValueError(f"protocol_relays entry must be a mapping (got {type(entry).__name__})")

    name = entry.get("name", "")
    rtype = entry.get("type", "")
    listen = entry.get("listen", "")
    if not (name and rtype and listen):
        raise ValueError(
            f"protocol_relays entry requires name/type/listen "
            f"(got name={name!r}, type={rtype!r}, listen={listen!r})"
        )

    validate_relay_type(rtype)

    upstream = entry.get("upstream") or {}
    if not isinstance(upstream, dict):
        raise ValueError(
            f"protocol_relays[{name}].upstream must be a mapping"
        )
    # `str()` on whatever is there would turn `host: [1]` into the
    # string "[1]", which is non-empty and therefore "present" — a
    # config that validates and then fails DNS resolution on a name
    # nobody wrote.
    #
    # Truthiness before type, matching ``ca_file``/``ca_pem`` below: a
    # falsy host means "absent", whatever its type, and gets the
    # requires-host-and-port message rather than a type complaint. Only
    # a *truthy* non-string is a mistake worth naming.
    raw_host = upstream.get("host", "")
    if raw_host and not isinstance(raw_host, str):
        raise ValueError(
            f"protocol_relays[{name}].upstream.host must be a string "
            f"(got {type(raw_host).__name__})"
        )
    host = str(raw_host or "")
    # `port: "993"` and `port: 993.7` coerce on purpose — YAML makes both
    # easy to write and both mean a port. `port: true` does not: `bool`
    # is an `int` subclass in Python, so it would coerce to **1** and
    # connect to a port the operator never named.
    #
    # Unlike ``host`` above, this refuses a *falsy* bool too. There is
    # no reading of ``port: false`` — or of ``port: no``, which YAML 1.1
    # makes the same thing — so the type message is more use than the
    # range one, whereas a falsy host has always been the ordinary
    # spelling of "absent".
    raw_port = upstream.get("port", 0)
    if isinstance(raw_port, bool):
        raise ValueError(
            f"protocol_relays[{name}].upstream.port must be a number "
            f"(got bool) — note that YAML reads bare yes/no/on/off as "
            f"booleans; quote the port if you meant a number"
        )
    try:
        port = int(raw_port or 0)
    except (TypeError, ValueError):
        port = 0
    if not host or not (1 <= port <= 65535):
        raise ValueError(
            f"protocol_relays[{name}].upstream requires host and "
            f"port in [1, 65535]"
        )

    tls = bool(upstream.get("tls", True))
    ca_file = upstream.get("ca_file", "") or ""
    if not isinstance(ca_file, str):
        raise ValueError(
            f"protocol_relays[{name}].upstream.ca_file must be a path "
            f"string (got {type(ca_file).__name__})"
        )
    ca_pem = upstream.get("ca_pem", "") or ""
    if not isinstance(ca_pem, str):
        raise ValueError(
            f"protocol_relays[{name}].upstream.ca_pem must be a PEM "
            f"string (got {type(ca_pem).__name__})"
        )
    if ca_pem and "-----BEGIN CERTIFICATE-----" not in ca_pem:
        raise ValueError(
            f"protocol_relays[{name}].upstream.ca_pem does not look like "
            f"PEM — expected a '-----BEGIN CERTIFICATE-----' block. To "
            f"point at a file on disk, use upstream.ca_file."
        )
    # ca_file is the operator-facing form; the CLI reads it and hands the
    # proxy the resolved ca_pem. Both set at once is ambiguous about
    # which one wins, so say so instead of picking silently.
    if ca_file and ca_pem:
        raise ValueError(
            f"protocol_relays[{name}].upstream sets both ca_file and "
            f"ca_pem; use one. ca_file is read at deploy time and becomes "
            f"ca_pem in the proxy's config."
        )
    servername = upstream.get("tls_servername", "") or ""
    if not isinstance(servername, str):
        raise ValueError(
            f"protocol_relays[{name}].upstream.tls_servername must be a "
            f"string (got {type(servername).__name__})"
        )
    # These only mean something on a TLS connection. Silently ignoring
    # them on a plaintext upstream would read as "the certificate is
    # verified" in a config review when nothing is verified at all.
    if not tls:
        for key, value in (
            ("ca_file", ca_file),
            ("ca_pem", ca_pem),
            ("tls_servername", servername),
        ):
            if value:
                raise ValueError(
                    f"protocol_relays[{name}].upstream.{key} requires "
                    f"upstream.tls: true (got tls: false, which connects "
                    f"in plaintext and verifies nothing)"
                )

    policy = entry.get("policy") or {}
    # `upstream` refuses a non-mapping outright; `policy` used to guard
    # with `isinstance` and no else branch, so a mistyped `policy:` —
    # a list, a bare string — skipped every check below it in silence,
    # `write_mode` included. The relay then reached `policy.get(...)` on
    # a list and died with an `AttributeError` naming nothing. This is
    # the block that gates writes to a mailbox; it says so instead.
    if policy and not isinstance(policy, dict):
        raise ValueError(
            f"protocol_relays[{name}].policy must be a mapping "
            f"(got {type(policy).__name__})"
        )
    if isinstance(policy, dict):
        mode = policy.get("write_mode")
        if mode is not None:
            if not isinstance(mode, str) or mode.lower() not in _WRITE_MODES:
                raise ValueError(
                    f"protocol_relays[{name}].policy.write_mode must be one "
                    f"of {', '.join(sorted(_WRITE_MODES))} (got {mode!r})"
                )
            # readonly is the older spelling of the same thing. Both set and
            # disagreeing is ambiguous, and guessing which the operator meant
            # is exactly the wrong call for a policy that gates writes.
            if "readonly" in policy:
                implied = "none" if policy.get("readonly") else "full"
                if implied != mode.lower():
                    raise ValueError(
                        f"protocol_relays[{name}].policy sets readonly="
                        f"{policy.get('readonly')!r} and write_mode={mode!r}, "
                        f"which contradict. Use write_mode alone."
                    )
        for key in ("folder_allowlist", "folder_denylist"):
            value = policy.get(key)
            if value is not None and not isinstance(value, list):
                raise ValueError(
                    f"protocol_relays[{name}].policy.{key} must be a list "
                    f"(got {type(value).__name__})"
                )

    auth = entry.get("auth") or {}
    if not isinstance(auth, dict):
        raise ValueError(f"protocol_relays[{name}].auth must be a mapping")
    if source_validator is not None:
        for key in ("user_source", "password_source"):
            value = auth.get(key, "") or ""
            if value:
                source_validator(str(value))
