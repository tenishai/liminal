"""Operator-only tools (cabal#233): a card's ``requires_operator`` flag.

The gate runs in every mode. Single-cabal trusts the verified token's own
cabal_scope; sovereign trusts only the server-side grant; auth-off refuses.
"""

from __future__ import annotations

import time

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from liminal.protocol import Context, ToolResult, ToolSpec
from liminal.protocol.card import validate_card
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import (
    MultiIssuerJWKSVerifier,
    SqlitePolicyStore,
    StaticKeySetVerifier,
    create_app,
)
from liminal.server.app import operator_only_tools
from liminal.server.mcp_types import ERROR_UNAUTHORIZED

SVC = "archivist@rd"


class _OpsHandler:
    """`ops.open` is unflagged; `ops.admin` is operator-only."""

    def tools(self) -> list[ToolSpec]:
        schema = {"type": "object", "properties": {}}
        return [
            ToolSpec(name="open", description="anyone", input_schema=schema),
            ToolSpec(name="admin", description="operator", input_schema=schema),
        ]

    def capability_card(self) -> dict:
        return {
            "handler": "ops",
            "description": "operator-only test handler",
            "tools": [
                {"name": "open", "description": "anyone"},
                {"name": "admin", "description": "operator", "requires_operator": True},
            ],
        }

    async def dispatch(self, name: str, payload: dict, ctx: Context) -> ToolResult:
        return ToolResult.json({"ran": name})


def _registry() -> Registry:
    reg = Registry()
    register_explicit(reg, "ops", _OpsHandler())
    return reg


def _key() -> RSAKey:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    k = RSAKey.import_key(pem)
    k.ensure_kid()
    return k


def _mint(key: RSAKey, *, iss: str = "cabal-core", aud: str = "liminal", **claims) -> str:
    now = int(time.time())
    payload = {
        "iss": iss, "sub": "rook-primus", "aud": aud, "iat": now, "exp": now + 60,
        "cabal_persona": "rook",
    }
    payload.update(claims)
    return jwt.encode({"alg": "RS256", "kid": key.kid, "typ": "JWT"}, payload, key)


async def _rpc(client: AsyncClient, tok: str | None, method: str, params: dict | None = None) -> dict:
    headers = {"Authorization": f"Bearer {tok}"} if tok else {}
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers=headers,
    )
    return r.json()


async def _call(client, tok, tool):
    return await _rpc(client, tok, "tools/call", {"name": tool, "arguments": {}})


async def _listed(client, tok) -> set[str]:
    body = await _rpc(client, tok, "tools/list")
    return {t["name"] for t in body["result"]["tools"]}


def _assert_operator_refused(body: dict) -> None:
    assert body["error"]["code"] == ERROR_UNAUTHORIZED
    assert "operator-only" in body["error"]["message"]


# ---- the card carries the flag through discovery -------------------------


def test_card_flag_parses_and_defaults_false() -> None:
    card = validate_card(_OpsHandler().capability_card())
    flags = {t.name: t.requires_operator for t in card.tools}
    assert flags == {"open": False, "admin": True}


def test_operator_only_tools_derived_from_registry() -> None:
    assert operator_only_tools(_registry()) == frozenset({"ops.admin"})


# ---- single-cabal: the verified token's own scope ------------------------


@pytest_asyncio.fixture
async def single():
    key = _key()
    app = create_app(
        jwt_verifier=StaticKeySetVerifier(key_set=KeySet([key])), registry=_registry()
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c, key


@pytest.mark.asyncio
async def test_single_operator_and_dispatch_allowed(single) -> None:
    client, key = single
    tok = _mint(key, cabal_scope=["dispatch", "operator"])
    body = await _call(client, tok, "ops.admin")
    assert body["result"]["isError"] is False
    assert "ops.admin" in await _listed(client, tok)


@pytest.mark.asyncio
async def test_single_scope_fallback_claim_allowed(single) -> None:
    client, key = single
    tok = _mint(key, scope=["dispatch", "operator"])
    body = await _call(client, tok, "ops.admin")
    assert body["result"]["isError"] is False


@pytest.mark.asyncio
async def test_single_dispatch_only_refused_and_hidden(single) -> None:
    client, key = single
    tok = _mint(key, cabal_scope=["dispatch"])
    _assert_operator_refused(await _call(client, tok, "ops.admin"))
    assert await _listed(client, tok) == {"ops.open"}


@pytest.mark.asyncio
async def test_single_unflagged_tool_unaffected(single) -> None:
    client, key = single
    tok = _mint(key, cabal_scope=["dispatch"])
    body = await _call(client, tok, "ops.open")
    assert body["result"]["isError"] is False


# ---- sovereign: the server-side grant, never the token -------------------


@pytest_asyncio.fixture
async def sov(tmp_path):
    kp, ks = _key(), _key()
    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=KeySet([kp]), expected_issuer="rd-cabal", expected_audience=SVC
            ),
            "shaz-cabal": StaticKeySetVerifier(
                key_set=KeySet([ks]), expected_issuer="shaz-cabal", expected_audience=SVC
            ),
        },
        parents=frozenset({"rd-cabal"}),
    )
    store = SqlitePolicyStore(str(tmp_path / "policy.db"), parent_issuer="rd-cabal")
    app = create_app(jwt_verifier=verifier, registry=_registry(), policy_store=store)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c, ks, store
    store.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["operator", "admin:*"])
async def test_sov_grant_with_operator_allowed(sov, scope) -> None:
    client, ks, store = sov
    await store.grant("shaz-cabal", "rook", scopes={scope}, allowed_handlers=None)
    tok = _mint(ks, iss="shaz-cabal", aud=SVC)
    body = await _call(client, tok, "ops.admin")
    assert body["result"]["isError"] is False
    assert "ops.admin" in await _listed(client, tok)


@pytest.mark.asyncio
async def test_sov_grant_without_operator_refused_and_audited(sov) -> None:
    client, ks, store = sov
    await store.grant("shaz-cabal", "rook", scopes={"dispatch"}, allowed_handlers=None)
    tok = _mint(ks, iss="shaz-cabal", aud=SVC)
    _assert_operator_refused(await _call(client, tok, "ops.admin"))
    assert await _listed(client, tok) == {"ops.open"}
    denies = [r for r in await store.audit() if r.action == "access_deny"]
    assert denies and denies[0].detail["tool"] == "ops.admin"
    assert denies[0].detail["required_scope"] == "operator"
    # The unflagged tool still runs under the same grant.
    assert (await _call(client, tok, "ops.open"))["result"]["isError"] is False


@pytest.mark.asyncio
async def test_sov_foreign_token_operator_claim_ignored(sov) -> None:
    client, ks, store = sov
    await store.grant("shaz-cabal", "rook", scopes={"dispatch"}, allowed_handlers=None)
    # A foreign cabal minting itself operator must not satisfy the gate.
    tok = _mint(
        ks, iss="shaz-cabal", aud=SVC,
        cabal_scope=["dispatch", "operator"], scope=["dispatch", "operator"],
    )
    _assert_operator_refused(await _call(client, tok, "ops.admin"))


# ---- auth-off: no verified identity, so no operator ----------------------


@pytest_asyncio.fixture
async def authoff(monkeypatch):
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    app = create_app(registry=_registry())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_authoff_operator_tool_refused(authoff) -> None:
    body = await _call(authoff, None, "ops.admin")
    _assert_operator_refused(body)
    assert "auth disabled" in body["error"]["message"]
    assert await _listed(authoff, None) == {"ops.open"}


@pytest.mark.asyncio
async def test_authoff_unflagged_tool_unaffected(authoff) -> None:
    body = await _call(authoff, None, "ops.open")
    assert body["result"]["isError"] is False
