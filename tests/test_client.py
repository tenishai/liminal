"""MCP client tests — driven against the real ASGI app over httpx
ASGITransport. Both sync and async clients covered.
"""

from __future__ import annotations

import json

import httpx
import pytest

from liminal.client import (
    AsyncMCPClient,
    MCPClient,
    MCPRemoteError,
    MCPTransportError,
    Tool,
)


@pytest.fixture
def async_http(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


def _sync_mock_handler():
    """Build a handler that fakes a minimal MCP server: initialize +
    tools/list + tools/call (scratchpad set/get) + ping. Enough to
    exercise the sync client's surface."""
    storage: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.read()
        import json as _json

        try:
            payload = _json.loads(body)
        except Exception:
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "bad json"}})
        method = payload.get("method")
        rid = payload.get("id")
        if method == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-06-18", "serverInfo": {"name": "liminal", "version": "0.1.0"}, "capabilities": {"tools": {}}}})
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "ping":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {}})
        if method == "tools/list":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {"tools": [{"name": "scratchpad.set", "description": "Set", "inputSchema": {"type": "object"}}, {"name": "scratchpad.get", "description": "Get", "inputSchema": {"type": "object"}}]}})
        if method == "tools/call":
            params = payload.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "scratchpad.set":
                storage[args["key"]] = args["value"]
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": "set"}], "isError": False}})
            if name == "scratchpad.get":
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": json.dumps({"value": storage.get(args["key"])})}], "isError": False}})
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "error": {"code": -32002, "message": f"unknown tool {name!r}"}})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}})

    return handler


@pytest.fixture
def sync_http():
    return httpx.Client(
        transport=httpx.MockTransport(_sync_mock_handler()),
        base_url="http://test",
    )


# ---- AsyncMCPClient -------------------------------------------------------


@pytest.mark.asyncio
async def test_async_initialize_returns_server_info(async_http, mint_token) -> None:
    client = AsyncMCPClient(
        base_url="http://test",
        token_provider=lambda: mint_token(),
        http_client=async_http,
    )
    result = await client.initialize()
    assert result["serverInfo"]["name"] == "liminal"
    assert client.server_capabilities  # populated
    await client.aclose()


@pytest.mark.asyncio
async def test_async_list_tools_auto_initializes(async_http, mint_token) -> None:
    """First call to list_tools should transparently handshake first."""
    client = AsyncMCPClient(
        base_url="http://test",
        token_provider=lambda: mint_token(),
        http_client=async_http,
    )
    tools = await client.list_tools()
    names = {t.name for t in tools}
    assert "scratchpad.set" in names
    assert all(isinstance(t, Tool) for t in tools)
    await client.aclose()


@pytest.mark.asyncio
async def test_async_call_tool_roundtrip(async_http, mint_token) -> None:
    client = AsyncMCPClient(
        base_url="http://test",
        token_provider=lambda: mint_token(persona="rook", sub="rook-primus"),
        http_client=async_http,
    )
    await client.call_tool(
        "scratchpad.set", {"key": "color", "value": "purple"}
    )
    outcome = await client.call_tool("scratchpad.get", {"key": "color"})
    assert outcome.is_error is False
    assert json.loads(outcome.content[0]["text"])["value"] == "purple"
    await client.aclose()


@pytest.mark.asyncio
async def test_async_remote_error_on_unknown_tool(async_http, mint_token) -> None:
    client = AsyncMCPClient(
        base_url="http://test",
        token_provider=lambda: mint_token(),
        http_client=async_http,
    )
    with pytest.raises(MCPRemoteError) as exc_info:
        await client.call_tool("ghost.summon", {})
    assert exc_info.value.code == -32002
    await client.aclose()


@pytest.mark.asyncio
async def test_async_transport_error_on_bad_url(mint_token) -> None:
    client = AsyncMCPClient(
        base_url="http://does-not-exist.invalid",
        token_provider=lambda: mint_token(),
    )
    with pytest.raises(MCPTransportError):
        await client.list_tools()
    await client.aclose()


@pytest.mark.asyncio
async def test_async_context_manager_closes(async_http, mint_token) -> None:
    async with AsyncMCPClient(
        base_url="http://test",
        token_provider=lambda: mint_token(),
        http_client=async_http,
    ) as client:
        await client.ping()
    # No assertion on close-state — just verify __aexit__ ran cleanly


@pytest.mark.asyncio
async def test_async_token_provider_called_per_request(async_http, mint_token) -> None:
    call_count = {"n": 0}

    def provider():
        call_count["n"] += 1
        return mint_token()

    client = AsyncMCPClient(
        base_url="http://test",
        token_provider=provider,
        http_client=async_http,
    )
    # initialize sends: initialize (no auth) + notifications/initialized (auth)
    await client.list_tools()
    await client.list_tools()
    # 3 authenticated calls: notify (initialized), tools/list, tools/list
    assert call_count["n"] >= 3
    await client.aclose()


# ---- Sync MCPClient -------------------------------------------------------


def test_sync_list_tools_works(sync_http, mint_token) -> None:
    client = MCPClient(
        base_url="http://test",
        token_provider=lambda: mint_token(),
        http_client=sync_http,
    )
    tools = client.list_tools()
    assert any(t.name == "scratchpad.set" for t in tools)


def test_sync_call_tool_roundtrip(sync_http, mint_token) -> None:
    client = MCPClient(
        base_url="http://test",
        token_provider=lambda: mint_token(persona="rook", sub="rook-primus"),
        http_client=sync_http,
    )
    client.call_tool("scratchpad.set", {"key": "k", "value": "v"})
    outcome = client.call_tool("scratchpad.get", {"key": "k"})
    assert json.loads(outcome.content[0]["text"])["value"] == "v"


def test_sync_remote_error_propagates(sync_http, mint_token) -> None:
    client = MCPClient(
        base_url="http://test",
        token_provider=lambda: mint_token(),
        http_client=sync_http,
    )
    with pytest.raises(MCPRemoteError) as exc:
        client.call_tool("ghost.summon", {})
    assert exc.value.code == -32002


def test_sync_context_manager(sync_http, mint_token) -> None:
    with MCPClient(
        base_url="http://test",
        token_provider=lambda: mint_token(),
        http_client=sync_http,
    ) as client:
        client.ping()


def test_tool_outcome_text_property() -> None:
    """text concatenates text content blocks; non-text blocks are skipped."""
    from liminal.client import ToolCallOutcome

    o = ToolCallOutcome(
        content=[
            {"type": "text", "text": "hello "},
            {"type": "json", "data": {"x": 1}},
            {"type": "text", "text": "world"},
        ]
    )
    assert o.text == "hello world"


def test_tool_outcome_text_property_empty_when_no_text() -> None:
    from liminal.client import ToolCallOutcome

    o = ToolCallOutcome(content=[{"type": "json", "data": {}}])
    assert o.text == ""
