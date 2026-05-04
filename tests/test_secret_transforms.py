"""Tests for secret-injection transforms — google-jwt-bearer in particular."""

from __future__ import annotations

import io
import json
import threading
import time
import urllib.error
from unittest.mock import patch

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from transforms import get, known, register
from transforms.google_jwt_bearer import (
    GoogleJwtBearer,
    TransformError,
    _TokenBucket,
)


# ── Test fixtures ────────────────────────────────────────


@pytest.fixture(scope="module")
def sa_key_json() -> str:
    """Generate a syntactically valid service-account key JSON for tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return json.dumps({
        "type": "service_account",
        "client_email": "agent@test.iam.gserviceaccount.com",
        "private_key": pem,
        "token_uri": "https://oauth2.googleapis.com/token",
    })


def _fake_oauth_response(token: str = "ya29.faketoken", expires_in: int = 3600):
    """Build a fake urlopen response with a Google OAuth token payload."""
    body = json.dumps({"access_token": token, "expires_in": expires_in}).encode()

    class _FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return body

    return _FakeResp()


# ── Registry ──────────────────────────────────────────────


class TestRegistry:
    def test_google_jwt_bearer_registered(self):
        assert "google-jwt-bearer" in known()
        assert get("google-jwt-bearer") is GoogleJwtBearer

    def test_unknown_transform_raises(self):
        with pytest.raises(KeyError, match="unknown transform"):
            get("nonexistent")

    def test_register_custom(self):
        class Dummy:
            def __init__(self, secret, config):
                pass

            def get_value(self):
                return "x"

        register("test-only", Dummy)
        try:
            assert get("test-only") is Dummy
        finally:
            from transforms import _REGISTRY
            _REGISTRY.pop("test-only", None)


# ── Token bucket ─────────────────────────────────────────


class TestTokenBucket:
    def test_starts_full(self):
        b = _TokenBucket(rate_per_hour=10)
        # Capacity = 10, so 10 immediate takes succeed, 11th fails.
        for _ in range(10):
            assert b.take() is True
        assert b.take() is False

    def test_refills_over_time(self):
        b = _TokenBucket(rate_per_hour=3600)  # 1 token/sec
        for _ in range(3600):
            b.take()
        assert b.take() is False
        # Rewind monotonic to simulate elapsed time
        b._last -= 2  # pretend 2 seconds passed
        assert b.take() is True
        assert b.take() is True
        assert b.take() is False

    def test_capacity_floor(self):
        # Even rate=0 must give at least 1 token of capacity (floor).
        b = _TokenBucket(rate_per_hour=0)
        assert b.take() is True


# ── Construction ─────────────────────────────────────────


class TestConstruction:
    def test_minimal_valid(self, sa_key_json):
        t = GoogleJwtBearer(
            sa_key_json,
            {"scopes": ["https://www.googleapis.com/auth/gmail.readonly"]},
        )
        assert t._scopes == ["https://www.googleapis.com/auth/gmail.readonly"]
        assert t._client_email == "agent@test.iam.gserviceaccount.com"

    def test_missing_scopes(self, sa_key_json):
        with pytest.raises(TransformError, match="scopes is required"):
            GoogleJwtBearer(sa_key_json, {})

    def test_empty_scopes_list(self, sa_key_json):
        with pytest.raises(TransformError, match="scopes is required"):
            GoogleJwtBearer(sa_key_json, {"scopes": []})

    def test_invalid_json(self):
        with pytest.raises(TransformError, match="not valid JSON"):
            GoogleJwtBearer("not json", {"scopes": ["a"]})

    def test_missing_required_field(self):
        bad = json.dumps({"client_email": "x@example.com"})  # no private_key
        with pytest.raises(TransformError, match="missing required field"):
            GoogleJwtBearer(bad, {"scopes": ["a"]})

    def test_token_uri_defaults_to_oauth2_googleapis(self, sa_key_json):
        t = GoogleJwtBearer(sa_key_json, {"scopes": ["a"]})
        assert t._token_uri == "https://oauth2.googleapis.com/token"
        assert t._audience == "https://oauth2.googleapis.com/token"

    def test_token_uri_in_sa_json_is_ignored(self):
        """The SA JSON's token_uri must NOT redirect the POST. The audience
        is the single source of truth — without this guard, a hostile or
        malformed SA JSON could redirect the signed assertion to an
        attacker-controlled host."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        sa = json.dumps({
            "type": "service_account",
            "client_email": "agent@test.iam.gserviceaccount.com",
            "private_key": pem,
            "token_uri": "https://attacker.example/steal",  # ignored
        })
        t = GoogleJwtBearer(sa, {"scopes": ["a"]})
        assert t._token_uri == "https://oauth2.googleapis.com/token"

    def test_audience_must_be_https(self, sa_key_json):
        with pytest.raises(TransformError, match="must be https"):
            GoogleJwtBearer(
                sa_key_json,
                {"scopes": ["a"], "audience": "http://oauth2.googleapis.com/token"},
            )

    def test_audience_must_be_in_allowlist(self, sa_key_json):
        with pytest.raises(TransformError, match="not in allowlist"):
            GoogleJwtBearer(
                sa_key_json,
                {"scopes": ["a"], "audience": "https://attacker.example/token"},
            )

    def test_audience_accounts_google_allowed(self, sa_key_json):
        t = GoogleJwtBearer(
            sa_key_json,
            {"scopes": ["a"], "audience": "https://accounts.google.com/o/oauth2/token"},
        )
        assert t._token_uri == "https://accounts.google.com/o/oauth2/token"


# ── Token minting and caching ────────────────────────────


class TestGetValue:
    def test_mints_on_first_call(self, sa_key_json):
        t = GoogleJwtBearer(sa_key_json, {"scopes": ["a"]})
        with patch(
            "transforms.google_jwt_bearer.urllib.request.urlopen",
            return_value=_fake_oauth_response("ya29.first", 3600),
        ) as m:
            assert t.get_value() == "ya29.first"
            assert m.call_count == 1

    def test_cache_hit_no_remint(self, sa_key_json):
        t = GoogleJwtBearer(sa_key_json, {"scopes": ["a"]})
        with patch(
            "transforms.google_jwt_bearer.urllib.request.urlopen",
            return_value=_fake_oauth_response("ya29.cached", 3600),
        ) as m:
            t.get_value()
            t.get_value()
            t.get_value()
            assert m.call_count == 1

    def test_cache_refreshes_near_expiry(self, sa_key_json):
        t = GoogleJwtBearer(
            sa_key_json,
            {"scopes": ["a"], "refresh_margin": 100},
        )
        responses = [
            _fake_oauth_response("ya29.first", 3600),
            _fake_oauth_response("ya29.second", 3600),
        ]
        with patch(
            "transforms.google_jwt_bearer.urllib.request.urlopen",
            side_effect=responses,
        ):
            assert t.get_value() == "ya29.first"
            # Walk the clock forward to within the refresh margin.
            t._cached_expiry = time.time() + 50
            assert t.get_value() == "ya29.second"

    def test_rate_limit_blocks_excess_mints(self, sa_key_json):
        t = GoogleJwtBearer(
            sa_key_json,
            {"scopes": ["a"], "mint_rate_per_hour": 1},
        )
        with patch(
            "transforms.google_jwt_bearer.urllib.request.urlopen",
            return_value=_fake_oauth_response("ya29.x", 3600),
        ):
            t.get_value()
            # Force cache to look stale.
            t._cached_expiry = 0
            with pytest.raises(TransformError, match="rate limit"):
                t.get_value()

    def test_http_error_raises_transform_error(self, sa_key_json):
        t = GoogleJwtBearer(sa_key_json, {"scopes": ["a"]})
        err = urllib.error.HTTPError(
            "https://oauth2.googleapis.com/token",
            403,
            "Forbidden",
            {},
            io.BytesIO(b'{"error": "invalid_grant"}'),
        )
        with patch(
            "transforms.google_jwt_bearer.urllib.request.urlopen",
            side_effect=err,
        ):
            with pytest.raises(TransformError, match="HTTP 403"):
                t.get_value()

    def test_url_error_raises_transform_error(self, sa_key_json):
        t = GoogleJwtBearer(sa_key_json, {"scopes": ["a"]})
        err = urllib.error.URLError("connection refused")
        with patch(
            "transforms.google_jwt_bearer.urllib.request.urlopen",
            side_effect=err,
        ):
            with pytest.raises(TransformError, match="network"):
                t.get_value()

    def test_missing_access_token_raises(self, sa_key_json):
        t = GoogleJwtBearer(sa_key_json, {"scopes": ["a"]})

        class _Empty:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b'{"expires_in": 3600}'

        with patch(
            "transforms.google_jwt_bearer.urllib.request.urlopen",
            return_value=_Empty(),
        ):
            with pytest.raises(TransformError, match="malformed"):
                t.get_value()

    def test_assertion_format(self, sa_key_json):
        """Sanity-check that the JWT we send to Google has three parts."""
        t = GoogleJwtBearer(sa_key_json, {"scopes": ["s1", "s2"]})
        captured = {}

        def _capture(req, timeout):
            captured["data"] = req.data
            captured["url"] = req.full_url
            return _fake_oauth_response("ya29.x", 3600)

        with patch(
            "transforms.google_jwt_bearer.urllib.request.urlopen",
            side_effect=_capture,
        ):
            t.get_value()

        assert captured["url"] == "https://oauth2.googleapis.com/token"
        body = captured["data"].decode()
        assert "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer" in body
        # assertion=<header>.<claims>.<signature>
        assert body.count(".") >= 2

    def test_concurrent_get_value_one_mint(self, sa_key_json):
        """Five threads racing on a cold cache must trigger exactly one mint:
        the lock around get_value serializes them and the second-through-fifth
        threads see the cache populated by the first."""
        t = GoogleJwtBearer(sa_key_json, {"scopes": ["a"]})
        mint_count = [0]
        lock = threading.Lock()

        def _slow_mint(req, timeout):
            with lock:
                mint_count[0] += 1
            time.sleep(0.05)
            return _fake_oauth_response("ya29.shared", 3600)

        results = []
        results_lock = threading.Lock()

        # Patch once at module scope so all threads share the same mock.
        with patch(
            "transforms.google_jwt_bearer.urllib.request.urlopen",
            side_effect=_slow_mint,
        ):
            def _worker():
                v = t.get_value()
                with results_lock:
                    results.append(v)

            threads = [threading.Thread(target=_worker) for _ in range(5)]
            for th in threads:
                th.start()
            for th in threads:
                th.join()

        assert all(r == "ya29.shared" for r in results)
        assert mint_count[0] == 1
