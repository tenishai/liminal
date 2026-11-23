"""liminal#228: refuse tokens whose subject cabal has revoked.

The verifier checks cabal's `GET /auth/revocations` list after signature and
claims hold. HTTP is mocked with httpx.MockTransport, as in
test_credential_resolver.py.
"""

from __future__ import annotations

import time

import httpx
import pytest
import structlog.testing
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from liminal.server.auth import (
    AuthError,
    IssuerConfig,
    MultiIssuerJWKSVerifier,
    StaticKeySetVerifier,
    URLJWKSVerifier,
    build_multi_issuer_verifier,
)
from liminal.server.revocations import RevocationList

CABAL = "cabal-core"
SUB = "agent:ext-operator-local"


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


@pytest.fixture(scope="module")
def key() -> RSAKey:
    return _make_key()


def _mint(key: RSAKey, *, iat: int, iss: str = CABAL, sub: str = SUB, aud="liminal") -> str:
    header = {"alg": "RS256", "kid": key.kid, "typ": "JWT"}
    payload = {
        "iss": iss, "sub": sub, "aud": aud, "iat": iat,
        "exp": int(time.time()) + 3600, "cabal_persona": "rook",
    }
    return jwt.encode(header, payload, key)


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class Cabal:
    """A mock cabal: `responses` is consumed one per request, last one sticks."""

    def __init__(self, *responses) -> None:
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


def _ok(revocations: dict[str, float]) -> httpx.Response:
    return httpx.Response(
        200, json={"revocations": revocations, "generated_at": int(time.time())}
    )


def _list(cabal: Cabal, *, issuer: str = CABAL, clock=None, ttl: float = 30.0) -> RevocationList:
    client = httpx.AsyncClient(transport=httpx.MockTransport(cabal), timeout=httpx.Timeout(5.0))
    return RevocationList(
        cabal_url="http://cabal-test/",
        issuer=issuer,
        token_provider=lambda: "svc-token",
        http_client=client,
        ttl_seconds=ttl,
        clock=clock or Clock(),
    )


def _verifier(key: RSAKey, revocations: RevocationList | None, issuer: str = CABAL):
    return StaticKeySetVerifier(
        key_set=KeySet([key]), expected_issuer=issuer, revocations=revocations
    )


NOW = int(time.time())
CUTOFF = NOW - 100


async def test_revoked_sub_issued_before_cutoff_is_refused(key) -> None:
    cabal = Cabal(_ok({SUB: CUTOFF}))
    v = _verifier(key, _list(cabal))
    with structlog.testing.capture_logs() as logs:
        with pytest.raises(AuthError) as exc:
            await v.verify(_mint(key, iat=CUTOFF - 1))
    # Same refusal the caller sees for an expired token; the cutoff stays out.
    assert str(exc.value) == "token expired"
    assert str(CUTOFF) not in str(exc.value)
    assert any(e.get("reason") == "revoked" for e in logs)
    req = cabal.requests[0]
    assert str(req.url) == "http://cabal-test/auth/revocations"
    assert req.headers["authorization"] == "Bearer svc-token"
    # The bearer never reaches a log line.
    assert all("svc-token" not in repr(e) for e in logs)


async def test_url_jwks_verifier_refuses_revoked_sub(key) -> None:
    v = URLJWKSVerifier(jwks_url="http://cabal-test/.well-known/jwks.json",
                        revocations=_list(Cabal(_ok({SUB: CUTOFF}))))
    v._cached = KeySet([key])
    v._cached_at = time.monotonic()
    with pytest.raises(AuthError, match="token expired"):
        await v.verify(_mint(key, iat=CUTOFF - 1))


@pytest.mark.parametrize("iat", [CUTOFF, CUTOFF + 1])
async def test_same_sub_issued_at_or_after_cutoff_passes(key, iat) -> None:
    v = _verifier(key, _list(Cabal(_ok({SUB: CUTOFF}))))
    claims = await v.verify(_mint(key, iat=iat))
    assert claims.agent_name == SUB


async def test_other_sub_passes(key) -> None:
    v = _verifier(key, _list(Cabal(_ok({SUB: CUTOFF}))))
    claims = await v.verify(_mint(key, iat=CUTOFF - 1, sub="agent:someone-else"))
    assert claims.agent_name == "agent:someone-else"


async def test_list_never_applies_to_another_issuer(key) -> None:
    # A list labelled for cabal-core, wired (wrongly) onto cabal-b's verifier,
    # must not touch cabal-b's tokens, and is never even fetched.
    cabal = Cabal(_ok({SUB: CUTOFF}))
    v = _verifier(key, _list(cabal, issuer=CABAL), issuer="cabal-b")
    claims = await v.verify(_mint(key, iat=CUTOFF - 1, iss="cabal-b"))
    assert claims.issuer == "cabal-b"
    assert cabal.requests == []


async def test_multi_issuer_applies_list_only_to_its_issuer(key) -> None:
    key_b = _make_key()
    cabal = Cabal(_ok({SUB: CUTOFF}))
    rl = _list(cabal, issuer="cabal-a")
    v = MultiIssuerJWKSVerifier(
        registry={
            "cabal-a": StaticKeySetVerifier(KeySet([key]), "cabal-a", "svc", revocations=rl),
            "cabal-b": StaticKeySetVerifier(KeySet([key_b]), "cabal-b", "svc"),
        }
    )
    with pytest.raises(AuthError, match="token expired"):
        await v.verify(_mint(key, iat=CUTOFF - 1, iss="cabal-a", aud="svc"))
    claims = await v.verify(_mint(key_b, iat=CUTOFF - 1, iss="cabal-b", aud="svc"))
    assert claims.issuer == "cabal-b" and claims.agent_name == SUB


def test_build_multi_issuer_wires_list_only_to_named_issuer() -> None:
    rl = RevocationList(cabal_url="http://a", issuer="cabal-a", token_provider=lambda: "")
    v = build_multi_issuer_verifier(
        [IssuerConfig("cabal-a", "http://a/jwks", parent=True),
         IssuerConfig("cabal-b", "http://b/jwks")],
        service_audience="svc",
        revocations=rl,
    )
    assert v.registry["cabal-a"].revocations is rl
    assert v.registry["cabal-b"].revocations is None


@pytest.mark.parametrize(
    "failure",
    [httpx.Response(404, text="not found"), httpx.ConnectError("refused")],
    ids=["older-cabal-404", "cabal-down"],
)
async def test_never_fetched_accepts_and_warns_once(key, failure) -> None:
    clock = Clock()
    cabal = Cabal(failure)
    v = _verifier(key, _list(cabal, clock=clock))
    with structlog.testing.capture_logs() as logs:
        for _ in range(3):
            assert (await v.verify(_mint(key, iat=CUTOFF - 1))).agent_name == SUB
        clock.t += 31  # next window: asked again, still no second warning
        assert (await v.verify(_mint(key, iat=CUTOFF - 1))).agent_name == SUB
    assert len(cabal.requests) == 2  # once per window, not per request
    warnings = [e for e in logs if e["log_level"] == "warning"]
    assert [e["event"] for e in warnings] == ["auth.revocations.unavailable"]


async def test_refresh_failure_keeps_last_good_list(key) -> None:
    clock = Clock()
    cabal = Cabal(_ok({SUB: CUTOFF}), httpx.Response(503), httpx.ConnectError("down"))
    v = _verifier(key, _list(cabal, clock=clock))
    token = _mint(key, iat=CUTOFF - 1)
    with pytest.raises(AuthError):
        await v.verify(token)
    with structlog.testing.capture_logs() as logs:
        for _ in range(2):
            clock.t += 31
            with pytest.raises(AuthError, match="token expired"):
                await v.verify(token)
    assert len(cabal.requests) == 3
    assert [e["event"] for e in logs if e["log_level"] == "warning"] == [
        "auth.revocations.refresh_failed_keeping_last"
    ] * 2


async def test_malformed_body_counts_as_failure(key) -> None:
    cabal = Cabal(httpx.Response(200, json={"revocations": [SUB]}))
    v = _verifier(key, _list(cabal))
    assert (await v.verify(_mint(key, iat=CUTOFF - 1))).agent_name == SUB


async def test_list_refreshes_after_ttl(key) -> None:
    clock = Clock()
    cabal = Cabal(_ok({}), _ok({SUB: CUTOFF}))
    v = _verifier(key, _list(cabal, clock=clock, ttl=30))
    token = _mint(key, iat=CUTOFF - 1)
    await v.verify(token)  # empty list: accepted
    clock.t += 29
    await v.verify(token)  # inside the TTL: no fetch, still accepted
    assert len(cabal.requests) == 1
    clock.t += 1
    with pytest.raises(AuthError, match="token expired"):
        await v.verify(token)  # TTL reached: refetched, now revoked
    assert len(cabal.requests) == 2


async def test_failed_signature_never_fetches(key) -> None:
    cabal = Cabal(_ok({}))
    v = _verifier(key, _list(cabal))
    with pytest.raises(AuthError, match="signature"):
        await v.verify(_mint(_make_key(), iat=NOW))
    assert cabal.requests == []


async def test_auth_disabled_does_no_fetch(monkeypatch, registry) -> None:
    """Auth-off has no verifier, so nothing can ever ask cabal for the list."""
    from httpx import ASGITransport, AsyncClient

    from liminal.server import create_app

    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    fetched: list[str] = []

    def boom(self, *a, **k):  # noqa: ARG001
        fetched.append("x")
        raise AssertionError("revocation list fetched under auth-off")

    monkeypatch.setattr(RevocationList, "_refresh", boom)
    app = create_app(jwt_verifier=None, registry=registry)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 200 and "error" not in r.json()
    assert fetched == []


# ---- CLI wiring -----------------------------------------------------------


def _serve(monkeypatch, argv: list[str]):
    import uvicorn

    from liminal import cli

    monkeypatch.delenv("LIMINAL_AUTH_DISABLED", raising=False)
    monkeypatch.setenv("LIMINAL_CABAL_TOKEN", "svc-token")
    captured: dict = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.setdefault("app", app))
    assert cli.main(["serve", *argv]) == 0
    return captured["app"].state.jwt_verifier


def test_cli_single_cabal_checks_its_issuer(monkeypatch) -> None:
    v = _serve(monkeypatch, [
        "--jwks-url", "http://cabal.test/.well-known/jwks.json",
        "--cabal-url", "http://cabal.test", "--issuer", "cabal-x",
        "--revocation-ttl", "12",
    ])
    assert v.revocations.issuer == "cabal-x"
    assert v.revocations.url == "http://cabal.test/auth/revocations"
    assert v.revocations.ttl_seconds == 12
    assert v.revocations.token_provider() == "svc-token"


def test_cli_without_cabal_url_has_no_check(monkeypatch) -> None:
    monkeypatch.delenv("LIMINAL_CABAL_URL", raising=False)
    v = _serve(monkeypatch, ["--jwks-url", "http://cabal.test/.well-known/jwks.json"])
    assert v.revocations is None


def test_cli_sovereign_checks_parent_only(monkeypatch, tmp_path) -> None:
    reg = tmp_path / "trust.toml"
    reg.write_text(
        'service_audience = "svc"\n'
        '[[issuer]]\nid = "home"\njwks_uri = "http://home/jwks"\nparent = true\n'
        'admin_personas = ["op"]\n'
        '[[issuer]]\nid = "partner"\njwks_uri = "http://partner/jwks"\n'
    )
    v = _serve(monkeypatch, [
        "--trust-registry", str(reg), "--policy-db", str(tmp_path / "p.db"),
        "--cabal-url", "http://home",
    ])
    assert v.registry["home"].revocations.issuer == "home"
    assert v.registry["partner"].revocations is None
