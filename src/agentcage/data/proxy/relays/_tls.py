"""Upstream TLS policy shared by the IMAP and SMTP relays.

Lives under ``data/proxy/relays/`` next to ``_validate`` for the same
reason: both sides of the trust boundary import the same code. The CLI
imports it as ``agentcage.data.proxy.relays._tls``; the proxy container
imports it as ``relays._tls``.

Stdlib only — the proxy environment does not have the CLI package on
its path.

Deliberately one module rather than a copy in each relay. The other
small helpers (``_resolve_credential``, ``_ConnRateLimiter``) are
duplicated across imap.py/smtp.py for code-shape parity, but a drifting
copy of *this* one silently downgrades certificate verification on one
protocol and not the other, which is exactly the class of bug that
never shows up in a passing test run.
"""

from __future__ import annotations

import ssl
from typing import Optional


def build_upstream_ssl_context(
    *,
    tls: bool,
    ca_pem: str = "",
) -> Optional[ssl.SSLContext]:
    """Build the SSLContext for a relay's upstream connection.

    Returns ``None`` when ``tls`` is false — the caller then connects in
    plaintext.

    The context always starts from the proxy container's system CA
    store, which is what a public mail host needs (Migadu, Gmail,
    Fastmail). ``ca_pem`` is *added* to that store, for upstreams it
    cannot cover: a self-hosted mail server behind a private CA, or a
    local decrypting daemon such as Proton Mail Bridge, which mints its
    own self-signed certificate at setup time.

    Additive, not exclusive: a relay configured with an extra anchor
    still trusts every public CA. That keeps one relay's private
    certificate from being a reason the next one can't reach a normal
    upstream, and matches how ``SSL_CERT_FILE``-style configuration
    behaves everywhere else. The cost is that ``ca_pem`` does not pin —
    a public CA that mis-issues for the same name still satisfies the
    check.

    Verification and hostname checking stay on in every branch. There is
    deliberately no "skip verification" mode: an unverified upstream is
    an unauthenticated one, and the relay hands it real credentials.
    When the upstream is addressed by IP (so its certificate name can
    never match), add the certificate and name it with
    ``tls_servername`` — see :func:`upstream_connect_kwargs`.
    """
    if not tls:
        return None
    ctx = ssl.create_default_context()
    if ca_pem:
        # load_verify_locations on a context that already loaded the
        # system store appends to it — create_default_context() did that
        # load, so this is strictly additive.
        ctx.load_verify_locations(cadata=ca_pem)
    return ctx


def upstream_connect_kwargs(
    *,
    tls: bool,
    ca_pem: str = "",
    tls_servername: str = "",
) -> dict:
    """Return the TLS kwargs for ``asyncio.open_connection``.

    ``tls_servername`` overrides the name presented in SNI and checked
    against the certificate, which the caller needs when ``upstream.host``
    is an IP literal: a certificate cannot be issued for an address the
    operator picked out of a container subnet, and IP-address SANs are
    rare in self-signed output.

    Omitted entirely when there is no TLS context, because
    ``asyncio.open_connection`` rejects ``server_hostname`` on a
    plaintext connection instead of ignoring it.
    """
    ctx = build_upstream_ssl_context(tls=tls, ca_pem=ca_pem)
    kwargs: dict = {"ssl": ctx}
    if ctx is not None and tls_servername:
        kwargs["server_hostname"] = tls_servername
    return kwargs
