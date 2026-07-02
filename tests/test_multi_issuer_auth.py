"""Multi-issuer verifier + list-aware aud — federation Part 1 (limenal#19).

Independent of the FastAPI routing layer; exercises the verifier directly.
"""

from __future__ import annotations

import time

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from limenal.server.auth import (
    AuthError,
    IssuerConfig,
    MultiIssuerJWKSVerifier,
    StaticKeySetVerifier,
    URLJWKSVerifier,
    build_multi_issuer_verifier,
)

SVC_AUD = "archivist@rd"


def _make_key() -> RSAKey:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key = RSAKey.import_key(pem)
    key.ensure_kid()
    return key


def _mint(key: RSAKey, *, iss: str, aud=SVC_AUD, sub="rook-primus",
          persona="rook", ttl: int = 60, **extra) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "kid": key.kid, "typ": "JWT"}
    payload = {
        "iss": iss, "sub": sub, "aud": aud,
        "iat": now, "exp": now + ttl, "cabal_persona": persona,
    }
    payload.update(extra)
    return jwt.encode(header, payload, key)


def _static(key: RSAKey, issuer: str, aud: str | None = SVC_AUD) -> StaticKeySetVerifier:
    return StaticKeySetVerifier(
        key_set=KeySet([key]), expected_issuer=issuer, expected_audience=aud
    )


@pytest.fixture
def two_cabals():
    """Two independent issuers, each its own keypair + verifier."""
    key_a, key_b = _make_key(), _make_key()
    verifier = MultiIssuerJWKSVerifier(
        registry={
            "cabal-a": _static(key_a, "cabal-a"),
            "cabal-b": _static(key_b, "cabal-b"),
        },
        parents=frozenset({"cabal-a"}),
    )
    return key_a, key_b, verifier


# ---- routing --------------------------------------------------------------


@pytest.mark.asyncio
async def test_routes_by_issuer(two_cabals) -> None:
    key_a, key_b, verifier = two_cabals
    claims_a = await verifier.verify(_mint(key_a, iss="cabal-a"))
    assert claims_a.issuer == "cabal-a"
    assert claims_a.identity == "rook"
    claims_b = await verifier.verify(_mint(key_b, iss="cabal-b", persona="raven"))
    assert claims_b.issuer == "cabal-b"
    assert claims_b.identity == "raven"


@pytest.mark.asyncio
async def test_untrusted_issuer_rejected(two_cabals) -> None:
    key_a, _key_b, verifier = two_cabals
    with pytest.raises(AuthError, match="untrusted issuer"):
        await verifier.verify(_mint(key_a, iss="cabal-c"))


@pytest.mark.asyncio
async def test_missing_iss_rejected(two_cabals) -> None:
    key_a, _key_b, verifier = two_cabals
    # iss omitted entirely -> _peek_iss returns None.
    tok = _mint(key_a, iss="cabal-a")
    # Re-mint without iss by hand.
    now = int(time.time())
    tok = jwt.encode(
        {"alg": "RS256", "kid": key_a.kid, "typ": "JWT"},
        {"sub": "x", "aud": SVC_AUD, "iat": now, "exp": now + 60, "cabal_persona": "p"},
        key_a,
    )
    with pytest.raises(AuthError, match="missing iss"):
        await verifier.verify(tok)


@pytest.mark.asyncio
async def test_cross_key_rejected(two_cabals) -> None:
    """A token claiming iss=cabal-a but signed with cabal-b's key routes to
    cabal-a's verifier and fails the signature check — the peek can't be
    exploited to borrow another issuer's trust."""
    _key_a, key_b, verifier = two_cabals
    forged = _mint(key_b, iss="cabal-a")  # lies about iss, signed by B
    with pytest.raises(AuthError):
        await verifier.verify(forged)


@pytest.mark.asyncio
async def test_garbage_token_rejected(two_cabals) -> None:
    _key_a, _key_b, verifier = two_cabals
    with pytest.raises(AuthError, match="missing iss"):
        await verifier.verify("not.a.jwt")


# ---- list-aware aud -------------------------------------------------------


@pytest.mark.asyncio
async def test_aud_list_accepted() -> None:
    key = _make_key()
    v = _static(key, "cabal-a", aud=SVC_AUD)
    claims = await v.verify(_mint(key, iss="cabal-a", aud=["other-svc", SVC_AUD]))
    assert claims.issuer == "cabal-a"


@pytest.mark.asyncio
async def test_aud_list_without_expected_rejected() -> None:
    key = _make_key()
    v = _static(key, "cabal-a", aud=SVC_AUD)
    with pytest.raises(AuthError, match="invalid_audience"):
        await v.verify(_mint(key, iss="cabal-a", aud=["other-svc", "third"]))


@pytest.mark.asyncio
async def test_aud_bare_string_still_works() -> None:
    key = _make_key()
    v = _static(key, "cabal-a", aud=SVC_AUD)
    claims = await v.verify(_mint(key, iss="cabal-a", aud=SVC_AUD))
    assert claims.raw["aud"] == SVC_AUD


@pytest.mark.asyncio
async def test_issuer_populated_single_verifier() -> None:
    """The additive issuer field is set even on the plain single-issuer path."""
    key = _make_key()
    v = _static(key, "cabal-solo")
    claims = await v.verify(_mint(key, iss="cabal-solo"))
    assert claims.issuer == "cabal-solo"


# ---- builder --------------------------------------------------------------


def test_build_happy_path() -> None:
    v = build_multi_issuer_verifier(
        [
            IssuerConfig("cabal-a", "https://a/jwks.json", parent=True),
            IssuerConfig("cabal-b", "https://b/jwks.json"),
        ],
        service_audience=SVC_AUD,
    )
    assert set(v.registry) == {"cabal-a", "cabal-b"}
    assert v.parents == frozenset({"cabal-a"})
    inner = v.registry["cabal-a"]
    assert isinstance(inner, URLJWKSVerifier)
    assert inner.expected_issuer == "cabal-a"
    assert inner.expected_audience == SVC_AUD


def test_build_requires_exactly_one_parent() -> None:
    with pytest.raises(ValueError, match="exactly one parent"):
        build_multi_issuer_verifier(
            [IssuerConfig("a", "https://a/jwks.json")], service_audience=SVC_AUD
        )
    with pytest.raises(ValueError, match="exactly one parent"):
        build_multi_issuer_verifier(
            [
                IssuerConfig("a", "https://a/jwks.json", parent=True),
                IssuerConfig("b", "https://b/jwks.json", parent=True),
            ],
            service_audience=SVC_AUD,
        )


def test_build_rejects_duplicate_ids() -> None:
    with pytest.raises(ValueError, match="duplicate issuer"):
        build_multi_issuer_verifier(
            [
                IssuerConfig("a", "https://a/jwks.json", parent=True),
                IssuerConfig("a", "https://a2/jwks.json"),
            ],
            service_audience=SVC_AUD,
        )


def test_build_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        build_multi_issuer_verifier([], service_audience=SVC_AUD)


# ---- per-issuer blast-radius isolation (real URLJWKSVerifier) --------------


def _jwks_body(key: RSAKey) -> dict:
    return {"keys": [key.as_dict(private=False)]}


@pytest.mark.asyncio
async def test_per_issuer_outage_isolation() -> None:
    """One issuer's JWKS endpoint being down denies only that issuer's callers.

    Exercises the production composition (real URLJWKSVerifiers with per-issuer
    httpx clients), not the StaticKeySetVerifier stand-in — the load-bearing
    security claim of the design (spec §Security notes).
    """
    key_a, key_b = _make_key(), _make_key()

    def down(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    def serves_b(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_jwks_body(key_b))

    va = URLJWKSVerifier(
        jwks_url="https://a.invalid/jwks.json",
        expected_issuer="cabal-a",
        expected_audience=SVC_AUD,
    )
    vb = URLJWKSVerifier(
        jwks_url="https://b.invalid/jwks.json",
        expected_issuer="cabal-b",
        expected_audience=SVC_AUD,
    )
    va._client = httpx.AsyncClient(transport=httpx.MockTransport(down))
    vb._client = httpx.AsyncClient(transport=httpx.MockTransport(serves_b))
    verifier = MultiIssuerJWKSVerifier(
        registry={"cabal-a": va, "cabal-b": vb},
        parents=frozenset({"cabal-a"}),
    )
    try:
        # B verifies despite A being down...
        assert (await verifier.verify(_mint(key_b, iss="cabal-b"))).issuer == "cabal-b"
        # ...A's outage denies its own callers (does not resolve/allow)...
        with pytest.raises(httpx.HTTPStatusError):
            await verifier.verify(_mint(key_a, iss="cabal-a"))
        # ...and B is unaffected by A's failure — isolation holds.
        assert (await verifier.verify(_mint(key_b, iss="cabal-b"))).issuer == "cabal-b"
    finally:
        await va._client.aclose()
        await vb._client.aclose()
