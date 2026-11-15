"""Standing-token exchange at the verifier (sovereign, opt-in per issuer).

Independent of the FastAPI routing layer; exercises the verifier directly.
The issuer is an httpx mock that counts what it was sent.
"""

from __future__ import annotations

import time

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from liminal.server import auth
from liminal.server.auth import (
    AudienceError,
    AuthError,
    ExchangingVerifier,
    IssuerConfig,
    MultiIssuerJWKSVerifier,
    StaticKeySetVerifier,
    build_multi_issuer_verifier,
)

ISS = "cabal-a"
SVC_AUD = "gateway"
STANDING_AUD = "cabal-a"
EXCHANGE_URI = "https://issuer.test/auth/exchange"


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


def _mint(key: RSAKey, *, aud: str, sub: str = "agent:rook", persona: str | None = "rook",
          ttl: int = 900, iss: str = ISS) -> str:
    now = int(time.time())
    payload = {"iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl}
    if persona is not None:
        payload["cabal_persona"] = persona
    return jwt.encode({"alg": "RS256", "kid": key.kid, "typ": "JWT"}, payload, key)


class _Issuer:
    """The issuer's exchange route: counts calls and records what it was sent."""

    def __init__(self, respond) -> None:
        self.calls = 0
        self.bearers: list[str] = []
        self._respond = respond

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        self.bearers.append(request.headers.get("authorization", ""))
        assert str(request.url) == EXCHANGE_URI and request.method == "POST"
        return self._respond(request)


def _verifier(key: RSAKey, issuer: _Issuer, **kw) -> ExchangingVerifier:
    v = ExchangingVerifier(
        gateway=StaticKeySetVerifier(
            key_set=KeySet([key]), expected_issuer=ISS, expected_audience=SVC_AUD
        ),
        exchange_uri=EXCHANGE_URI,
        **kw,
    )
    v._client = httpx.AsyncClient(transport=httpx.MockTransport(issuer))
    return v


def _answers(token: str):
    return lambda request: httpx.Response(200, json={"access_token": token})


async def test_a_token_aimed_at_the_service_never_reaches_the_issuer():
    key = _make_key()
    issuer = _Issuer(lambda r: httpx.Response(500))
    claims = await _verifier(key, issuer).verify(_mint(key, aud=SVC_AUD))
    assert claims.identity == "rook" and issuer.calls == 0


async def test_a_standing_token_is_exchanged_and_the_answer_is_what_counts():
    key = _make_key()
    # The standing token names no persona; the exchanged one does. The caller
    # gets the exchanged token's claims, never the standing token's.
    standing = _mint(key, aud=STANDING_AUD, persona=None)
    issuer = _Issuer(_answers(_mint(key, aud=SVC_AUD, sub="rook", persona="rook")))
    v = _verifier(key, issuer)

    claims = await v.verify(standing)

    assert (claims.identity, claims.agent_name, claims.issuer) == ("rook", "rook", ISS)
    assert claims.raw["aud"] == SVC_AUD
    assert issuer.bearers == [f"Bearer {standing}"]


async def test_the_exchange_is_reused_and_the_standing_token_is_not_kept():
    key = _make_key()
    standing = _mint(key, aud=STANDING_AUD)
    issuer = _Issuer(_answers(_mint(key, aud=SVC_AUD)))
    v = _verifier(key, issuer)

    for _ in range(3):
        await v.verify(standing)

    assert issuer.calls == 1
    assert standing not in repr(v._cache)


async def test_a_forged_token_is_never_sent_to_the_issuer():
    key, attacker = _make_key(), _make_key()
    issuer = _Issuer(_answers(_mint(key, aud=SVC_AUD)))
    v = _verifier(key, issuer)

    # Signed by a key the issuer does not own, and one claiming another issuer.
    for forged in (_mint(attacker, aud=STANDING_AUD), _mint(key, aud=STANDING_AUD, iss="cabal-x")):
        with pytest.raises(AuthError) as exc:
            await v.verify(forged)
        assert not isinstance(exc.value, AudienceError)
    assert issuer.calls == 0


@pytest.mark.parametrize("status", [401, 403])
async def test_a_refusal_denies_and_is_remembered_briefly(status):
    key = _make_key()
    standing = _mint(key, aud=STANDING_AUD)
    issuer = _Issuer(lambda r: httpx.Response(status, json={"detail": "revoked"}))
    v = _verifier(key, issuer)

    for _ in range(3):
        with pytest.raises(AuthError, match="refused"):
            await v.verify(standing)
    assert issuer.calls == 1

    # Once the window passes the issuer is asked again.
    v._cache = {k: (0.0, value) for k, (_, value) in v._cache.items()}
    with pytest.raises(AuthError, match="refused"):
        await v.verify(standing)
    assert issuer.calls == 2


async def test_an_issuer_that_is_away_denies_and_is_not_remembered():
    key = _make_key()
    standing = _mint(key, aud=STANDING_AUD)

    def away(request):
        raise httpx.ConnectError("no route")

    for respond in (away, lambda r: httpx.Response(503)):
        issuer = _Issuer(respond)
        v = _verifier(key, issuer)
        for _ in range(2):
            with pytest.raises(AuthError) as exc:
                await v.verify(standing)
            assert standing not in str(exc.value)
        assert issuer.calls == 2 and not v._cache


async def test_an_answer_aimed_elsewhere_is_refused_without_a_second_exchange():
    key = _make_key()
    issuer = _Issuer(_answers(_mint(key, aud="somewhere-else")))
    with pytest.raises(AudienceError):
        await _verifier(key, issuer).verify(_mint(key, aud=STANDING_AUD))
    assert issuer.calls == 1


@pytest.mark.parametrize("body", [{}, {"access_token": ""}, {"access_token": 7}, ["x"]])
async def test_an_answer_with_no_token_is_refused(body):
    key = _make_key()
    issuer = _Issuer(lambda r: httpx.Response(200, json=body))
    with pytest.raises(AuthError, match="no access_token"):
        await _verifier(key, issuer).verify(_mint(key, aud=STANDING_AUD))


async def test_the_reuse_window_never_outlives_the_exchanged_token():
    key = _make_key()
    standing = _mint(key, aud=STANDING_AUD)
    # Thirty seconds left is inside the expiry margin: verified, never reused.
    issuer = _Issuer(_answers(_mint(key, aud=SVC_AUD, ttl=30)))
    v = _verifier(key, issuer)
    await v.verify(standing)
    await v.verify(standing)
    assert issuer.calls == 2 and not v._cache

    # A long-lived answer is still reused for the window only.
    issuer = _Issuer(_answers(_mint(key, aud=SVC_AUD, ttl=86400)))
    v = _verifier(key, issuer, cache_seconds=120.0)
    await v.verify(standing)
    (deadline, _), = v._cache.values()
    assert deadline - time.monotonic() <= 120.0


async def test_the_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(auth, "EXCHANGE_CACHE_MAX", 2)
    key = _make_key()
    issuer = _Issuer(_answers(_mint(key, aud=SVC_AUD)))
    v = _verifier(key, issuer)
    for n in range(4):
        await v.verify(_mint(key, aud=STANDING_AUD, sub=f"agent:a{n}"))
    assert len(v._cache) == 2


# ---- the registry: off unless an issuer asks for it ----------------------


async def test_without_exchange_uri_a_standing_token_is_refused_as_before():
    key = _make_key()
    v = MultiIssuerJWKSVerifier(
        registry={ISS: StaticKeySetVerifier(
            key_set=KeySet([key]), expected_issuer=ISS, expected_audience=SVC_AUD
        )},
        parents=frozenset({ISS}),
    )
    with pytest.raises(AuthError, match="invalid_audience"):
        await v.verify(_mint(key, aud=STANDING_AUD))


def test_the_registry_wraps_only_the_issuers_that_set_exchange_uri():
    v = build_multi_issuer_verifier(
        [
            IssuerConfig(id="cabal-a", jwks_uri="https://a.test/jwks", parent=True,
                         exchange_uri=EXCHANGE_URI),
            IssuerConfig(id="cabal-b", jwks_uri="https://b.test/jwks"),
        ],
        service_audience=SVC_AUD,
    )
    assert isinstance(v.registry["cabal-a"], ExchangingVerifier)
    assert v.registry["cabal-a"].exchange_uri == EXCHANGE_URI
    assert not isinstance(v.registry["cabal-b"], ExchangingVerifier)


@pytest.mark.parametrize("bad", ["", "issuer.test/exchange", "file:///etc/passwd", 7])
def test_an_exchange_uri_that_is_not_http_is_a_registry_error(bad):
    with pytest.raises(ValueError, match="exchange_uri"):
        build_multi_issuer_verifier(
            [IssuerConfig(id="cabal-a", jwks_uri="https://a.test/jwks", parent=True,
                          exchange_uri=bad)],
            service_audience=SVC_AUD,
        )
