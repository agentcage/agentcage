"""Google service-account JWT-bearer transform.

Mints short-lived OAuth2 access tokens from a service-account private key
held only in proxy memory. The cage never sees the SA key — it sends
``Authorization: Bearer {{PLACEHOLDER}}`` and the proxy substitutes a
freshly minted (or cached) ``ya29.<...>`` access token at request time.

Token lifetime is whatever Google grants (typically 3600s); we refresh a
configurable margin before expiry. Mints are rate-limited per rule to
bound the damage if a malicious skill tries to spam the broker.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("agentcage.transforms.google_jwt_bearer")


_DEFAULT_AUDIENCE = "https://oauth2.googleapis.com/token"
_DEFAULT_REFRESH_MARGIN = 300  # refresh 5 min before Google says it expires
_DEFAULT_MINT_RATE_PER_HOUR = 60  # cap on actual mints per hour
_HTTP_TIMEOUT = 10  # seconds — applied to oauth2.googleapis.com round-trip

# Allowlist for the JWT audience / token POST target. The JWT `aud` claim
# and the actual POST URL are *the same value* — Google rejects the
# assertion otherwise — so a single config knob drives both, and we
# refuse anything outside this set. Without this, a hostile or malformed
# SA JSON could redirect the signed assertion to an attacker-controlled
# host (the JWT itself isn't a Google credential, but the redirection
# is a confirmation-of-life signal we shouldn't grant for free).
_ALLOWED_AUDIENCE_HOSTS = ("oauth2.googleapis.com", "accounts.google.com")


class TransformError(RuntimeError):
    """Raised when a transform cannot produce a value (config or mint failure).

    Bubbles up to the SecretInjector and surfaces as a flagged-error
    audit entry; the placeholder is left in place so the cage's request
    fails with an unauthenticated upstream response, not silent leakage.
    """


def _b64url(data: bytes) -> bytes:
    """RFC 7515 base64url encoding — strip trailing padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=")


class _TokenBucket:
    """Token bucket for mint rate limiting. Thread-safe."""

    def __init__(self, rate_per_hour: int) -> None:
        # Refill rate in tokens/sec; capacity = one hour of budget.
        self._capacity = max(1, int(rate_per_hour))
        self._tokens = float(self._capacity)
        self._refill_per_sec = self._capacity / 3600.0
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def take(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(
                self._capacity, self._tokens + elapsed * self._refill_per_sec
            )
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            return False


class GoogleJwtBearer:
    """Mint Google OAuth2 access tokens via the JWT-bearer flow.

    Private key never leaves this object. The cage receives only the
    minted access token, scoped to whatever was configured at deploy
    time. Tokens are cached in-process and refreshed before expiry.
    """

    def __init__(self, secret: str, config: dict) -> None:
        self._scopes: list[str] = list(config.get("scopes") or [])
        if not self._scopes:
            raise TransformError(
                "google-jwt-bearer: transform_config.scopes is required"
            )
        self._audience: str = str(
            config.get("audience") or _DEFAULT_AUDIENCE
        )
        self._validate_audience(self._audience)
        self._refresh_margin: int = int(
            config.get("refresh_margin", _DEFAULT_REFRESH_MARGIN)
        )
        rate = int(
            config.get("mint_rate_per_hour", _DEFAULT_MINT_RATE_PER_HOUR)
        )
        self._bucket = _TokenBucket(rate)

        try:
            sa = json.loads(secret)
        except json.JSONDecodeError as e:
            raise TransformError(
                f"google-jwt-bearer: SA key is not valid JSON: {e}"
            ) from e

        try:
            self._client_email = sa["client_email"]
            self._private_key_pem = sa["private_key"]
        except KeyError as e:
            raise TransformError(
                f"google-jwt-bearer: SA key missing required field: {e}"
            ) from e
        # The JWT `aud` claim and the POST target must match — Google
        # rejects the assertion otherwise — so we drive both from one
        # config knob and never trust `token_uri` from the SA JSON.
        self._token_uri = self._audience

        self._signing_key = self._load_private_key(self._private_key_pem)
        self._lock = threading.Lock()
        self._cached_token: str | None = None
        self._cached_expiry: float = 0.0

    @staticmethod
    def _validate_audience(url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            raise TransformError(
                f"google-jwt-bearer: audience must be https://, got '{url}'"
            )
        host = (parsed.hostname or "").lower()
        if not any(
            host == h or host.endswith("." + h) for h in _ALLOWED_AUDIENCE_HOSTS
        ):
            allowed = ", ".join(_ALLOWED_AUDIENCE_HOSTS)
            raise TransformError(
                f"google-jwt-bearer: audience host '{host}' not in "
                f"allowlist ({allowed})"
            )

    @staticmethod
    def _load_private_key(pem: str):
        # Lazy import — keeps the rest of the module unit-testable
        # without cryptography installed (we mock _mint instead).
        from cryptography.hazmat.primitives import serialization

        return serialization.load_pem_private_key(
            pem.encode("utf-8"), password=None
        )

    def get_value(self) -> str:
        """Return a valid access token, minting one if cache is stale."""
        with self._lock:
            now = time.time()
            if (
                self._cached_token
                and now + self._refresh_margin < self._cached_expiry
            ):
                return self._cached_token

            if not self._bucket.take():
                raise TransformError(
                    "google-jwt-bearer: mint rate limit exceeded"
                )

            token, expiry = self._mint(now)
            self._cached_token = token
            self._cached_expiry = expiry
            log.info(
                "google-jwt-bearer: minted token, scopes=%s, expires_in=%ds",
                " ".join(self._scopes),
                int(expiry - now),
            )
            return token

    def _mint(self, now: float) -> tuple[str, float]:
        """Build, sign, and exchange a JWT bearer assertion."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        header = {"alg": "RS256", "typ": "JWT"}
        claims = {
            "iss": self._client_email,
            "scope": " ".join(self._scopes),
            "aud": self._audience,
            "iat": int(now),
            "exp": int(now) + 3600,
        }
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode())
            + b"."
            + _b64url(json.dumps(claims, separators=(",", ":")).encode())
        )
        signature = self._signing_key.sign(
            signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
        assertion = signing_input + b"." + _b64url(signature)

        body = urllib.parse.urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion.decode("ascii"),
            }
        ).encode()
        req = urllib.request.Request(
            self._token_uri,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            log.error(
                "google-jwt-bearer: mint failed (HTTP %s): %s", e.code, detail
            )
            raise TransformError(
                f"google-jwt-bearer: mint failed (HTTP {e.code})"
            ) from e
        except urllib.error.URLError as e:
            log.error("google-jwt-bearer: mint failed (network): %s", e)
            raise TransformError(
                f"google-jwt-bearer: mint failed (network: {e.reason})"
            ) from e

        access_token = payload.get("access_token")
        expires_in = int(payload.get("expires_in") or 0)
        if not access_token or expires_in <= 0:
            raise TransformError(
                "google-jwt-bearer: malformed token response from Google"
            )
        return access_token, now + expires_in
