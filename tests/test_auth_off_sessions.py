"""Under auth-off, each MCP session gets its own scratchpad (liminal#192)."""

from __future__ import annotations

import json

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from liminal.server import create_app

INIT = {
    "jsonrpc": "2.0",
    "id": 0,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "t", "version": "0"},
    },
}
JSON_CT = {"Content-Type": "application/json"}


def _call(name: str, args: dict, rid: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }


def _value(resp) -> object:
    content = resp.json()["result"]["content"][0]["text"]
    return json.loads(content)["value"]


async def _session(client: AsyncClient) -> dict[str, str]:
    resp = await client.post("/mcp", json=INIT, headers=JSON_CT)
    sid = resp.headers.get("mcp-session-id")
    assert sid, "auth-off initialize must issue a session id"
    return {**JSON_CT, "Mcp-Session-Id": sid}


@pytest_asyncio.fixture
async def open_client(monkeypatch, registry):
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    monkeypatch.delenv("LIMINAL_ALLOWED_ORIGINS", raising=False)
    app = create_app(registry=registry)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_two_sessions_do_not_share_a_scratchpad(open_client):
    a = await _session(open_client)
    b = await _session(open_client)
    assert a["Mcp-Session-Id"] != b["Mcp-Session-Id"]
    await open_client.post("/mcp", json=_call("scratchpad.set", {"key": "plan", "value": "A"}), headers=a)
    await open_client.post("/mcp", json=_call("scratchpad.set", {"key": "plan", "value": "B"}), headers=b)
    await open_client.post("/mcp", json=_call("scratchpad.clear", {}), headers=b)

    got = await open_client.post("/mcp", json=_call("scratchpad.get", {"key": "plan"}), headers=a)
    assert _value(got) == "A"


@pytest.mark.asyncio
async def test_a_client_without_a_session_id_still_works(open_client):
    await open_client.post("/mcp", json=_call("scratchpad.set", {"key": "k", "value": 1}), headers=JSON_CT)
    got = await open_client.post("/mcp", json=_call("scratchpad.get", {"key": "k"}), headers=JSON_CT)
    assert _value(got) == 1


@pytest.mark.asyncio
async def test_no_session_id_is_issued_under_auth(monkeypatch, app):
    monkeypatch.delenv("LIMINAL_AUTH_DISABLED", raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.post("/mcp", json=INIT, headers=JSON_CT)
    assert resp.status_code == 200
    assert "mcp-session-id" not in resp.headers
