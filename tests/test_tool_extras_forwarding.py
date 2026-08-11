"""Verify that the `cabal_tool_extras` JWT claim reaches Context.extra
on the handler dispatch path.

Cabal embeds per-persona scoping config (web allowlist, files
allowlist, etc.) in the JWT claim. liminal extracts it during auth
and stuffs it into the Context the handler sees. End-to-end here uses
a stub handler that just echoes ctx.extra back; the substantive
"web with persona allowlist" assertion lives in the web-handler
tests (test_web_handler.test_per_persona_allowlist_via_ctx_extra),
which already pass and prove the receiving side.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import pytest
from joserfc import jwt

from liminal.protocol import Context, ToolResult, ToolSpec
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import StaticKeySetVerifier, create_app


class _EchoExtraHandler:
    """Handler that returns ctx.extra so the test can assert on it."""

    name = "echo-extra"

    def tools(self) -> list[ToolSpec]:
        return [
            ToolSpec(name="get_extra", description="return ctx.extra as JSON")
        ]

    def capability_card(self) -> dict[str, Any]:
        return {
            "handler": "echo-extra",
            "description": "test handler",
            "tools": [{"name": "get_extra", "description": "x"}],
        }

    async def dispatch(self, name: str, payload: dict, ctx: Context) -> ToolResult:
        return ToolResult.json({"extra": dict(ctx.extra)})


def _mint_with_extras(signing_key, extras: dict | None) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"}
    payload = {
        "iss": "cabal-core",
        "sub": "rook-primus",
        "aud": "liminal",
        "iat": now,
        "exp": now + 60,
        "cabal_persona": "rook",
        "cabal_scope": ["dispatch"],
    }
    if extras is not None:
        payload["cabal_tool_extras"] = extras
    return jwt.encode(header, payload, signing_key)


@pytest.fixture
def registry_with_echo():
    r = Registry()
    register_explicit(r, "echo-extra", _EchoExtraHandler())
    return r


@pytest.fixture
def app_with_echo(keyset, registry_with_echo):
    verifier = StaticKeySetVerifier(key_set=keyset)
    return create_app(jwt_verifier=verifier, registry=registry_with_echo)


@pytest.fixture
def client_with_echo(app_with_echo):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_with_echo),
        base_url="http://test",
    )


@pytest.mark.asyncio
async def test_tool_extras_claim_reaches_handler(
    signing_key, client_with_echo
) -> None:
    token = _mint_with_extras(
        signing_key,
        extras={"web.allowed_hosts": ["docs.python.org"], "marker": "rook-config"},
    )
    async with client_with_echo as c:
        r = await c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo-extra.get_extra", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    assert body.get("error") is None, body
    extra = json.loads(body["result"]["content"][0]["text"])["extra"]
    assert extra["marker"] == "rook-config"
    assert extra["web.allowed_hosts"] == ["docs.python.org"]


@pytest.mark.asyncio
async def test_missing_tool_extras_yields_empty_extra(
    signing_key, client_with_echo
) -> None:
    """A JWT without cabal_tool_extras must not break Context construction."""
    token = _mint_with_extras(signing_key, extras=None)
    async with client_with_echo as c:
        r = await c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo-extra.get_extra", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    assert body.get("error") is None, body
    extra = json.loads(body["result"]["content"][0]["text"])["extra"]
    assert extra == {}


@pytest.mark.asyncio
async def test_non_dict_tool_extras_fails_closed(signing_key, client_with_echo) -> None:
    """A malformed cabal_tool_extras claim (string, array) fails closed —
    all handler calls are denied rather than silently falling open."""
    token = _mint_with_extras(
        signing_key, extras="i-am-not-a-dict"  # type: ignore[arg-type]
    )
    async with client_with_echo as c:
        r = await c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo-extra.get_extra", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    # Malformed extras → deny all; error, not a successful tool result
    assert body.get("error") is not None
    assert body.get("result") is None
