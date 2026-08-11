"""Standalone-evaluation tests for liminal#1.

Three pieces:
  1. `scope` claim works as a fallback for `cabal_scope`
  2. `tool_extras` claim works as a fallback for `cabal_tool_extras`
  3. LIMINAL_AUTH_DISABLED=1 disables JWT enforcement at the route layer
     (with a startup banner; misconfiguration with a jwt_verifier raises
     at create_app)
"""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient
from joserfc import jwt

from liminal.handlers.scratchpad import ScratchpadHandler
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import StaticKeySetVerifier, create_app


@pytest.fixture
def mint_token_with_claims(signing_key):
    """Mint a token where the caller chooses which claim names to use."""
    def _mint(
        *,
        sub: str = "rook-primus",
        persona: str = "rook",
        scope_claim_name: str = "cabal_scope",
        scope_value: list[str] | None = None,
        extras_claim_name: str | None = None,
        extras_value: dict | None = None,
        ttl: int = 60,
    ) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"}
        payload = {
            "iss": "cabal-core",
            "sub": sub,
            "aud": "liminal",
            "iat": now,
            "exp": now + ttl,
            "cabal_persona": persona,
        }
        payload[scope_claim_name] = scope_value if scope_value is not None else ["dispatch"]
        if extras_claim_name is not None and extras_value is not None:
            payload[extras_claim_name] = extras_value
        return jwt.encode(header, payload, signing_key)

    return _mint


@pytest.fixture
def fresh_registry() -> Registry:
    r = Registry()
    register_explicit(r, "scratchpad", ScratchpadHandler())
    return r


# ---- Scope fallback --------------------------------------------------------


@pytest.mark.asyncio
async def test_scope_claim_accepted_as_fallback_for_cabal_scope(
    keyset, mint_token_with_claims, fresh_registry
) -> None:
    """A token minted with plain `scope: ["dispatch"]` (no `cabal_scope`)
    must be accepted — that's the standalone path."""
    app = create_app(
        jwt_verifier=StaticKeySetVerifier(key_set=keyset),
        registry=fresh_registry,
    )
    token = mint_token_with_claims(scope_claim_name="scope")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    assert body.get("error") is None, body


@pytest.mark.asyncio
async def test_token_with_neither_scope_claim_still_rejected(
    keyset, mint_token_with_claims, fresh_registry
) -> None:
    """Missing both scope variants → 401."""
    app = create_app(
        jwt_verifier=StaticKeySetVerifier(key_set=keyset),
        registry=fresh_registry,
    )
    # Mint with a bogus claim name so neither `cabal_scope` nor `scope` are set.
    token = mint_token_with_claims(scope_claim_name="some_other_claim")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    assert body.get("error") is not None
    assert "scope" in body["error"]["message"].lower()


# ---- tool_extras fallback --------------------------------------------------


@pytest.mark.asyncio
async def test_tool_extras_claim_accepted_as_fallback(
    keyset, mint_token_with_claims, fresh_registry
) -> None:
    """A token using plain `tool_extras` (no Cabal prefix) gets that data
    forwarded into Context.extra so handlers see it."""
    app = create_app(
        jwt_verifier=StaticKeySetVerifier(key_set=keyset),
        registry=fresh_registry,
    )
    extras = {"liminal.allowed_handlers": ["scratchpad"]}
    token = mint_token_with_claims(
        extras_claim_name="tool_extras", extras_value=extras
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    assert body.get("error") is None, body
    # The allowed_handlers filter is honored — scratchpad tools come back.
    tool_names = {t["name"] for t in body["result"]["tools"]}
    assert any(n.startswith("scratchpad.") for n in tool_names)


# ---- LIMINAL_AUTH_DISABLED -------------------------------------------------


def test_auth_disabled_with_jwt_verifier_raises(
    monkeypatch, fresh_registry, keyset
) -> None:
    """Setting LIMINAL_AUTH_DISABLED=1 AND passing a jwt_verifier is a
    configuration error — fail loudly at create_app."""
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    with pytest.raises(RuntimeError, match="LIMINAL_AUTH_DISABLED"):
        create_app(
            jwt_verifier=StaticKeySetVerifier(key_set=keyset),
            registry=fresh_registry,
        )


@pytest.mark.asyncio
async def test_auth_disabled_accepts_unauthenticated_requests(
    monkeypatch, fresh_registry
) -> None:
    """With LIMINAL_AUTH_DISABLED=1 and no jwt_verifier, requests without
    an Authorization header pass through."""
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    app = create_app(registry=fresh_registry)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            # NOTE: no Authorization header at all
        )
    body = r.json()
    assert body.get("error") is None, body
    assert "tools" in body["result"]


@pytest.mark.asyncio
async def test_no_auth_env_unset_still_rejects_unauth(fresh_registry, keyset) -> None:
    """Default behavior (env unset) is unchanged: auth required."""
    # Explicitly ensure env is clean for this test.
    import os
    os.environ.pop("LIMINAL_AUTH_DISABLED", None)
    app = create_app(
        jwt_verifier=StaticKeySetVerifier(key_set=keyset),
        registry=fresh_registry,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
    body = r.json()
    assert body.get("error") is not None
