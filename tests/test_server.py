"""MCP server end-to-end tests via real JSON-RPC over ASGI."""

from __future__ import annotations

import json

import pytest

# ---- healthz --------------------------------------------------------------


@pytest.mark.asyncio
async def test_healthz_returns_ok(client) -> None:
    r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# ---- initialize -----------------------------------------------------------


@pytest.mark.asyncio
async def test_initialize_handshake_no_auth_required(client) -> None:
    envelope = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "clientInfo": {"name": "test-client", "version": "0.0.0"},
            "capabilities": {},
        },
    }
    r = await client.post("/mcp", json=envelope)
    assert r.status_code == 200
    body = r.json()
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == 1
    assert body.get("error") is None
    assert body["result"]["serverInfo"]["name"] == "limenal"
    assert body["result"]["protocolVersion"] == "2025-06-18"
    assert "tools" in body["result"]["capabilities"]


@pytest.mark.asyncio
async def test_initialized_notification_returns_202(client) -> None:
    r = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        },
    )
    assert r.status_code == 202


# ---- ping ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_ping_no_auth_required(client) -> None:
    r = await client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 42, "method": "ping"}
    )
    assert r.status_code == 200
    assert r.json()["result"] == {}


# ---- auth gate -----------------------------------------------------------


@pytest.mark.asyncio
async def test_tools_list_requires_auth(client) -> None:
    r = await client.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    )
    body = r.json()
    assert body["error"]["code"] == -32001
    assert "missing" in body["error"]["message"].lower()


@pytest.mark.asyncio
async def test_tools_call_rejects_invalid_token(client) -> None:
    r = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "scratchpad.list", "arguments": {}},
        },
        headers={"Authorization": "Bearer not.a.real.token"},
    )
    body = r.json()
    assert body["error"]["code"] == -32001


@pytest.mark.asyncio
async def test_expired_token_rejected(client, mint_token) -> None:
    # mint with negative ttl so it's already expired
    expired = mint_token(ttl=-3600)
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {expired}"},
    )
    body = r.json()
    assert body["error"]["code"] == -32001
    assert "expired" in body["error"]["message"].lower()


@pytest.mark.asyncio
async def test_wrong_issuer_rejected(client, mint_token) -> None:
    bad = mint_token(iss="some-other-issuer")
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {bad}"},
    )
    body = r.json()
    assert body["error"]["code"] == -32001


@pytest.mark.asyncio
async def test_missing_persona_claim_rejected(client, signing_key) -> None:
    """A token with iss + sub + iat + exp but no cabal_persona should be
    rejected — we need the persona to route credentials."""
    import time

    from joserfc import jwt

    now = int(time.time())
    header = {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"}
    payload = {
        "iss": "cabal-core",
        "sub": "rook-primus",
        "aud": "limenal",
        "iat": now,
        "exp": now + 60,
        "cabal_scope": ["dispatch"],
        # no cabal_persona — that's the missing claim this test verifies
    }
    token = jwt.encode(header, payload, signing_key)
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert body["error"]["code"] == -32001
    assert "cabal_persona" in body["error"]["message"]


# ---- tools/list ----------------------------------------------------------


@pytest.mark.asyncio
async def test_tools_list_returns_prefixed_names(client, mint_token) -> None:
    token = mint_token()
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert body.get("error") is None, body
    names = [t["name"] for t in body["result"]["tools"]]
    assert "scratchpad.set" in names
    assert "scratchpad.get" in names
    # MCP spec uses camelCase
    assert "inputSchema" in body["result"]["tools"][0]


# ---- tools/call ----------------------------------------------------------


@pytest.mark.asyncio
async def test_tools_call_dispatches_to_scratchpad(client, mint_token) -> None:
    token = mint_token(persona="rook", sub="rook-primus")
    # SET
    r = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "scratchpad.set",
                "arguments": {"key": "color", "value": "blue"},
            },
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body.get("error") is None, body
    assert body["result"]["isError"] is False

    # GET — same persona + agent should see it
    r = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "scratchpad.get",
                "arguments": {"key": "color"},
            },
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert json.loads(body["result"]["content"][0]["text"])["value"] == "blue"


@pytest.mark.asyncio
async def test_tools_call_isolated_per_agent(client, mint_token) -> None:
    """rook-primus and rook-secundus are different agents — scratchpad
    isolates per (identity, agent_name)."""
    primus = mint_token(sub="rook-primus", persona="rook")
    secundus = mint_token(sub="rook-secundus", persona="rook")

    await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "scratchpad.set",
                "arguments": {"key": "secret", "value": "primus-only"},
            },
        },
        headers={"Authorization": f"Bearer {primus}"},
    )
    r = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "scratchpad.get",
                "arguments": {"key": "secret"},
            },
        },
        headers={"Authorization": f"Bearer {secundus}"},
    )
    body = r.json()
    assert json.loads(body["result"]["content"][0]["text"])["value"] is None


@pytest.mark.asyncio
async def test_tools_call_unknown_tool_returns_unknown_tool(client, mint_token) -> None:
    token = mint_token()
    r = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ghost.summon", "arguments": {}},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert body["error"]["code"] == -32002


@pytest.mark.asyncio
async def test_tools_call_unprefixed_name_returns_invalid_params(
    client, mint_token
) -> None:
    token = mint_token()
    r = await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "scratchpad", "arguments": {}},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert body["error"]["code"] == -32602


# ---- method routing -------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_method_returns_method_not_found(client, mint_token) -> None:
    token = mint_token()
    r = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/banish"},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = r.json()
    assert body["error"]["code"] == -32601


@pytest.mark.asyncio
async def test_invalid_json_body_rejected(client) -> None:
    r = await client.post(
        "/mcp",
        content="not json",
        headers={"Content-Type": "application/json"},
    )
    body = r.json()
    assert body["error"]["code"] == -32600


@pytest.mark.asyncio
async def test_malformed_envelope_rejected(client) -> None:
    r = await client.post(
        "/mcp", json={"jsonrpc": "1.0", "method": "tools/list"}
    )
    body = r.json()
    assert body["error"]["code"] == -32600


# ---- credential resolver ---------------------------------------------------


@pytest.mark.asyncio
async def test_credential_resolver_invoked_per_call(keyset, mint_token, registry) -> None:
    """When a credential_resolver is wired, the dispatcher's Context.credentials
    should contain whatever the resolver returns for (persona, handler)."""
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from limenal.server import StaticKeySetVerifier, create_app

    calls: list[tuple[str, str]] = []

    async def resolver(persona: str, handler: str) -> dict[str, str]:
        calls.append((persona, handler))
        return {"SLACK_TOKEN": f"sk-{persona}-{handler}"}

    app: FastAPI = create_app(
        jwt_verifier=StaticKeySetVerifier(key_set=keyset),
        registry=registry,
        credential_resolver=resolver,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        token = mint_token(persona="rook")
        await c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "scratchpad.set",
                    "arguments": {"key": "x", "value": "y"},
                },
            },
            headers={"Authorization": f"Bearer {token}"},
        )

    assert calls == [("rook", "scratchpad")]
