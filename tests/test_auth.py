"""Auth verifier unit tests — independent of the FastAPI routing layer."""

from __future__ import annotations

import time

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet

from limenal.server.auth import (
    AuthError,
    StaticKeySetVerifier,
    URLJWKSVerifier,
)


def _mint(signing_key, **overrides) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"}
    payload = {
        "iss": "cabal-core",
        "sub": "rook-primus",
        "aud": "limenal",
        "iat": now,
        "exp": now + 60,
        "cabal_persona": "rook",
    }
    payload.update(overrides)
    return jwt.encode(header, payload, signing_key)


def test_static_verifier_happy_path(signing_key, keyset) -> None:
    verifier = StaticKeySetVerifier(key_set=keyset)
    token = _mint(signing_key)
    claims = verifier.verify(token)
    assert claims.identity == "rook"
    assert claims.agent_name == "rook-primus"
    assert claims.raw["iss"] == "cabal-core"


def test_static_verifier_rejects_unsigned(keyset) -> None:
    verifier = StaticKeySetVerifier(key_set=keyset)
    with pytest.raises(AuthError):
        verifier.verify("not.a.real.jwt")


def test_static_verifier_falls_back_to_persona_claim(signing_key) -> None:
    """Accept `persona` as an alias for `cabal_persona` — useful for
    callers not running under the Cabal naming."""
    ks = KeySet([signing_key])
    token = _mint(signing_key, cabal_persona=None, persona="rook")
    # joserfc's encode drops None values? we'll mint deliberately:
    import time as _time

    now = int(_time.time())
    payload = {
        "iss": "cabal-core",
        "sub": "rook-primus",
        "iat": now,
        "exp": now + 60,
        "persona": "rook",
    }
    header = {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"}
    raw = jwt.encode(header, payload, signing_key)
    claims = StaticKeySetVerifier(key_set=ks).verify(raw)
    assert claims.identity == "rook"


def test_static_verifier_rejects_unexpected_issuer(signing_key, keyset) -> None:
    verifier = StaticKeySetVerifier(key_set=keyset)
    token = _mint(signing_key, iss="other-issuer")
    with pytest.raises(AuthError, match="unexpected iss"):
        verifier.verify(token)


def test_static_verifier_rejects_expired(signing_key, keyset) -> None:
    verifier = StaticKeySetVerifier(key_set=keyset)
    past = int(time.time()) - 3600
    token = _mint(signing_key, iat=past - 60, exp=past)
    with pytest.raises(AuthError, match="expired"):
        verifier.verify(token)


def test_static_verifier_rejects_future_iat(signing_key, keyset) -> None:
    verifier = StaticKeySetVerifier(key_set=keyset)
    future = int(time.time()) + 3600
    token = _mint(signing_key, iat=future)
    with pytest.raises(AuthError, match="future"):
        verifier.verify(token)


def test_url_verifier_caches_then_refreshes(signing_key, keyset) -> None:
    """Mock the JWKS endpoint; verify the verifier caches between calls
    and refreshes when the kid isn't in the cached set."""
    import httpx

    jwk_dict = signing_key.as_dict(private=False)
    jwk_dict["kid"] = signing_key.kid

    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, json={"keys": [jwk_dict]})

    transport = httpx.MockTransport(handler)
    verifier = URLJWKSVerifier(jwks_url="http://test/.well-known/jwks.json")
    verifier._client = httpx.Client(transport=transport, timeout=httpx.Timeout(5.0))

    # First call fetches
    verifier.verify(_mint(signing_key))
    assert call_count["n"] == 1

    # Second call uses cache
    verifier.verify(_mint(signing_key))
    assert call_count["n"] == 1


def test_url_verifier_refreshes_on_unknown_kid(signing_key) -> None:
    """If the cached set has the wrong kid, the verifier should re-fetch."""
    import httpx
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from joserfc.jwk import RSAKey

    # An "old" key on the first fetch, the "real" signing_key on the
    # second fetch (post-rotation).
    old_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    old_pem = old_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    old_key = RSAKey.import_key(old_pem)
    old_key.ensure_kid()
    old_jwk = old_key.as_dict(private=False)
    old_jwk["kid"] = old_key.kid

    real_jwk = signing_key.as_dict(private=False)
    real_jwk["kid"] = signing_key.kid

    fetch_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        fetch_count["n"] += 1
        if fetch_count["n"] == 1:
            return httpx.Response(200, json={"keys": [old_jwk]})
        return httpx.Response(200, json={"keys": [real_jwk]})

    transport = httpx.MockTransport(handler)
    verifier = URLJWKSVerifier(jwks_url="http://test/.well-known/jwks.json")
    verifier._client = httpx.Client(transport=transport, timeout=httpx.Timeout(5.0))

    # Should succeed by triggering a re-fetch
    claims = verifier.verify(_mint(signing_key))
    assert claims.identity == "rook"
    assert fetch_count["n"] == 2
