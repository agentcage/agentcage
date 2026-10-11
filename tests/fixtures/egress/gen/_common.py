"""Shared helpers for the egress corpus generators (not a corpus itself).

Puts the Python egress on ``sys.path`` (stubbing the proxy framework its
addon modules import, via the pytest conftest) and converts between the
corpus's language-neutral request contexts and ``InspectionContext``.
"""

from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
FIXTURES = ROOT / "tests" / "fixtures" / "egress"

# At the front, ahead of this directory: the generators are named after
# their corpora, and ``gen/inspectors.py`` would otherwise shadow the
# egress's ``inspectors`` package.
for _p in (str(ROOT / "tests"), str(ROOT / "src" / "agentcage" / "data" / "proxy")):
    while _p in sys.path:
        sys.path.remove(_p)
    sys.path.insert(0, _p)

# The pytest conftest stubs the proxy framework the addon modules import
# at top level, so they load on a machine without it.
import conftest  # noqa: E402,F401

from inspectors.base import InspectionContext  # noqa: E402
from inspectors.util import shannon_entropy  # noqa: E402


def noise(n: int, seed: str = "agentcage") -> bytes:
    """``n`` deterministic high-entropy bytes."""
    out = b""
    block = seed.encode()
    while len(out) < n:
        block = hashlib.sha256(block).digest()
        out += block
    return out[:n]


def ctx(*, url=None, host="api.example.com", method="POST", headers=(),
        content_type="application/json", body=None, text="utf-8",
        body_size=None, body_entropy="auto") -> dict:
    """A resolved, language-neutral request context.

    ``body`` is ``str`` (encoded UTF-8) or ``bytes``; ``text`` says how
    ``body_text`` is derived from the bytes (``"utf-8"``, ``"latin-1"``,
    or ``None`` for no text). ``body_size`` overrides the length (for a
    size check without a 10 MB fixture), ``body_entropy`` the entropy.
    Every derived field is written out, so a consumer never recomputes.
    """
    if isinstance(body, str):
        body = body.encode("utf-8")
    body_text = None
    if body and text:
        body_text = body.decode(text)
    if body_entropy == "auto":
        body_entropy = shannon_entropy(body) if body else None
    out = {
        "url": url if url is not None else f"https://{host}/v1/x",
        "host": host,
        "method": method,
        "headers": [list(h) for h in headers],
        "content_type": content_type,
        "body_b64": base64.b64encode(body).decode() if body is not None else None,
        "body_text": body_text,
        "body_size": body_size if body_size is not None else (len(body) if body else 0),
        "body_entropy": body_entropy,
    }
    return out


def _rev_b64(data: bytes) -> str:
    return base64.b64encode(data[::-1]).decode()


def _unrev_b64(text: str) -> bytes:
    return base64.b64decode(text)[::-1]


def hide(text: str) -> dict:
    """``{"b64r": ...}`` for a string that carries a credential-shaped
    sample: the base64 of its UTF-8 bytes *reversed*. Repository secret
    scanners read plain text and decode plain base64, so either form
    would have the test vectors mistaken for leaked keys (and a push
    refused); reversed, they no longer look like keys."""
    return {"b64r": _rev_b64(text.encode("utf-8"))}


def unhide(value):
    """The inverse of :func:`hide`; plain strings and ``None`` pass."""
    if isinstance(value, dict):
        return _unrev_b64(value["b64r"]).decode("utf-8")
    return value


def hide_ctx(spec: dict) -> dict:
    """A context with its URL, header values and body hidden (the body
    as ``body_b64r``, reversed like :func:`hide`)."""
    out = dict(spec)
    out["url"] = hide(spec["url"])
    out["headers"] = [[k, hide(v)] for k, v in spec["headers"]]
    if spec["body_text"] is not None:
        out["body_text"] = hide(spec["body_text"])
    body = out.pop("body_b64")
    out["body_b64r"] = (_rev_b64(base64.b64decode(body))
                        if body is not None else None)
    return out


def to_context(spec: dict) -> InspectionContext:
    if "body_b64r" in spec:
        body = (_unrev_b64(spec["body_b64r"])
                if spec["body_b64r"] is not None else None)
    else:
        body = (base64.b64decode(spec["body_b64"])
                if spec["body_b64"] is not None else None)
    return InspectionContext(
        url=unhide(spec["url"]), host=spec["host"], method=spec["method"],
        headers=[(k, unhide(v)) for k, v in spec["headers"]],
        content_type=spec["content_type"], body_bytes=body,
        body_text=unhide(spec["body_text"]), body_size=spec["body_size"],
        body_entropy=spec["body_entropy"],
    )


def verdict(r):
    if r is None:
        return None
    return {
        "inspector": r.inspector,
        "action": r.action,
        "reason": r.reason,
        "severity": r.severity,
        "metadata": dict(r.metadata),
    }
