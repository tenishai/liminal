"""Tests for the MCP proxy handler (limenal#3).

A mock upstream MCP server is implemented as an httpx MockTransport so
we can exercise the full forward path without a real network.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from limenal.handlers.mcp_proxy import (
    MCPProxyHandler,
    ProxyConfig,
    ProxyRegistrationError,
    register_proxies,
)
from limenal.handlers.scratchpad import ScratchpadHandler
from limenal.protocol import Context
from limenal.registry import Registry
from limenal.registry.discover import register_explicit

# ---- mock upstream MCP server --------------------------------------------


def _make_mock_upstream(
    *,
    tools: list[dict] | None = None,
    on_call: dict[str, Any] | None = None,
    captured: list[dict] | None = None,
):
    """Build an httpx MockTransport that simulates an MCP server.

    `tools` is what tools/list returns.
    `on_call` maps tool-name → result dict to return from tools/call.
    `captured` collects every request so tests can assert headers/payload.
    """
    tools = tools or [
        {"name": "search", "description": "Search.", "inputSchema": {"type": "object"}},
        {"name": "ping", "description": "Ping.", "inputSchema": {"type": "object"}},
    ]
    on_call = on_call or {"search": {"content": [{"type": "text", "text": "hit"}]}}

    def handler(request: httpx.Request) -> httpx.Response:
        if captured is not None:
            captured.append({
                "method": request.method,
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": request.read(),
            })
        body = json.loads(request.read())
        rid = body.get("id")
        method = body.get("method")
        params = body.get("params") or {}

        if method == "initialize":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": rid,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": "mock", "version": "1"},
                    "capabilities": {},
                },
            })
        if method == "tools/list":
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": rid, "result": {"tools": tools},
            })
        if method == "tools/call":
            tool_name = params.get("name")
            result = on_call.get(tool_name)
            if result is None:
                return httpx.Response(200, json={
                    "jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32002, "message": f"unknown tool {tool_name!r}"},
                })
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": rid, "result": result,
            })
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": "method not found"},
        })

    return handler


@pytest.fixture
def mock_http():
    handler = _make_mock_upstream()
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ---- handler startup + tool discovery -------------------------------------


@pytest.mark.asyncio
async def test_startup_fetches_upstream_tools(mock_http) -> None:
    config = ProxyConfig(
        prefix="upstream", upstream_url="http://test",
        auth_method="none", refresh_tools_interval_seconds=0,
    )
    handler = MCPProxyHandler(config=config, http_client=mock_http)
    await handler.startup()
    try:
        names = {t.name for t in handler.tools()}
        assert names == {"search", "ping"}
    finally:
        await handler.shutdown()


@pytest.mark.asyncio
async def test_dispatch_forwards_to_upstream(mock_http) -> None:
    config = ProxyConfig(
        prefix="upstream", upstream_url="http://test",
        auth_method="none", refresh_tools_interval_seconds=0,
    )
    handler = MCPProxyHandler(config=config, http_client=mock_http)
    await handler.startup()
    try:
        ctx = Context(identity="x", agent_name="x", credentials={})
        result = await handler.dispatch("search", {"q": "abc"}, ctx)
        assert result.is_error is False
        # Upstream returned a text content block — handler preserves it.
        assert result.content[0]["type"] == "text"
        assert result.content[0]["text"] == "hit"
    finally:
        await handler.shutdown()


@pytest.mark.asyncio
async def test_dispatch_returns_failure_on_upstream_error(mock_http) -> None:
    config = ProxyConfig(
        prefix="upstream", upstream_url="http://test",
        auth_method="none", refresh_tools_interval_seconds=0,
    )
    handler = MCPProxyHandler(config=config, http_client=mock_http)
    await handler.startup()
    try:
        ctx = Context(identity="x", agent_name="x", credentials={})
        # 'ghost' isn't in on_call → upstream returns JSON-RPC error
        result = await handler.dispatch("ghost", {}, ctx)
        assert result.is_error is True
        assert "upstream 'upstream'" in result.error
    finally:
        await handler.shutdown()


@pytest.mark.asyncio
async def test_dispatch_before_startup_returns_clear_error() -> None:
    config = ProxyConfig(
        prefix="upstream", upstream_url="http://test", auth_method="none",
    )
    handler = MCPProxyHandler(config=config)
    ctx = Context(identity="x", agent_name="x", credentials={})
    result = await handler.dispatch("search", {}, ctx)
    assert result.is_error is True
    assert "not started" in result.error


# ---- auth modes -----------------------------------------------------------


@pytest.mark.asyncio
async def test_bearer_auth_attaches_static_token() -> None:
    captured: list[dict] = []
    http = httpx.AsyncClient(transport=httpx.MockTransport(
        _make_mock_upstream(captured=captured)
    ))
    config = ProxyConfig(
        prefix="upstream", upstream_url="http://test",
        auth_method="bearer", bearer_token="sk-static-xyz",
        refresh_tools_interval_seconds=0,
    )
    handler = MCPProxyHandler(config=config, http_client=http)
    await handler.startup()
    try:
        ctx = Context(identity="x", agent_name="x", credentials={})
        await handler.dispatch("search", {}, ctx)
        # The tools/call request should carry the bearer token
        call_req = next(c for c in captured if b"tools/call" in c["body"])
        assert call_req["headers"].get("authorization") == "Bearer sk-static-xyz"
    finally:
        await handler.shutdown()


@pytest.mark.asyncio
async def test_service_token_auth_pulls_from_ctx_credentials() -> None:
    captured: list[dict] = []
    http = httpx.AsyncClient(transport=httpx.MockTransport(
        _make_mock_upstream(captured=captured)
    ))
    config = ProxyConfig(
        prefix="upstream", upstream_url="http://test",
        auth_method="service-token", credential_key="JIRA_TOKEN",
        refresh_tools_interval_seconds=0,
    )
    handler = MCPProxyHandler(config=config, http_client=http)
    await handler.startup()
    try:
        ctx = Context(
            identity="x", agent_name="x",
            credentials={"JIRA_TOKEN": "dynamic-token-from-resolver"},
        )
        await handler.dispatch("search", {}, ctx)
        call_req = next(c for c in captured if b"tools/call" in c["body"])
        assert (
            call_req["headers"].get("authorization")
            == "Bearer dynamic-token-from-resolver"
        )
    finally:
        await handler.shutdown()


@pytest.mark.asyncio
async def test_none_auth_sends_no_authorization_header() -> None:
    captured: list[dict] = []
    http = httpx.AsyncClient(transport=httpx.MockTransport(
        _make_mock_upstream(captured=captured)
    ))
    config = ProxyConfig(
        prefix="upstream", upstream_url="http://test",
        auth_method="none", refresh_tools_interval_seconds=0,
    )
    handler = MCPProxyHandler(config=config, http_client=http)
    await handler.startup()
    try:
        ctx = Context(identity="x", agent_name="x", credentials={})
        await handler.dispatch("search", {}, ctx)
        call_req = next(c for c in captured if b"tools/call" in c["body"])
        # AsyncMCPClient sends `Authorization: Bearer ` when token is empty;
        # accept either no header or an empty bearer (both signal "no auth").
        auth = call_req["headers"].get("authorization", "")
        assert auth in ("", "Bearer ")
    finally:
        await handler.shutdown()


# ---- config validation ---------------------------------------------------


def test_config_rejects_empty_prefix() -> None:
    with pytest.raises(ValueError, match="prefix"):
        ProxyConfig(prefix="", upstream_url="http://x").validate()


def test_config_rejects_prefix_with_dot() -> None:
    with pytest.raises(ValueError, match="prefix"):
        ProxyConfig(prefix="bad.name", upstream_url="http://x").validate()


def test_config_requires_bearer_token_for_bearer_mode() -> None:
    with pytest.raises(ValueError, match="bearer_token"):
        ProxyConfig(
            prefix="x", upstream_url="http://x", auth_method="bearer",
        ).validate()


def test_config_requires_credential_key_for_service_token_mode() -> None:
    with pytest.raises(ValueError, match="credential_key"):
        ProxyConfig(
            prefix="x", upstream_url="http://x", auth_method="service-token",
        ).validate()


# ---- register_proxies ----------------------------------------------------


def test_register_proxies_adds_to_registry() -> None:
    reg = Registry()
    configs = [
        ProxyConfig(prefix="jira", upstream_url="http://jira", auth_method="none"),
        ProxyConfig(prefix="slack", upstream_url="http://slack", auth_method="none"),
    ]
    handlers = register_proxies(reg, configs)
    assert {"jira", "slack"}.issubset(set(reg.names()))
    assert len(handlers) == 2
    assert isinstance(handlers[0], MCPProxyHandler)


def test_register_proxies_rejects_prefix_collision_with_existing() -> None:
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    with pytest.raises(ProxyRegistrationError, match="collides"):
        register_proxies(reg, [
            ProxyConfig(prefix="scratchpad", upstream_url="http://x"),
        ])


def test_register_proxies_rejects_duplicate_prefixes() -> None:
    reg = Registry()
    with pytest.raises(ProxyRegistrationError, match="duplicate"):
        register_proxies(reg, [
            ProxyConfig(prefix="jira", upstream_url="http://a"),
            ProxyConfig(prefix="jira", upstream_url="http://b"),
        ])


def test_register_proxies_rejects_invalid_config() -> None:
    reg = Registry()
    with pytest.raises(ProxyRegistrationError, match="invalid proxy config"):
        register_proxies(reg, [
            ProxyConfig(prefix="bad.name", upstream_url="http://x"),
        ])
