"""limenal#32 — the MCP client OMITS the Authorization header entirely when the
token_provider returns an empty string (the natural thing in a no-auth
deployment, ``LIMENAL_AUTH_DISABLED=1``), instead of emitting ``Bearer `` — an
empty value httpx rejects as an illegal header before the request leaves the
client.

``httpx.ASGITransport`` (used for in-process tests elsewhere) does NOT enforce
header legality, so the bug hid behind green in-process tests while real-network
calls failed. These use ``httpx.MockTransport`` to capture the exact headers the
client puts on each request and assert on the header's presence/absence.
"""

from __future__ import annotations

import httpx
import pytest

from limenal.client.mcp import AsyncMCPClient, MCPClient, _auth_header

_OK = {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_auth_header_helper_omits_on_falsy_token() -> None:
    assert _auth_header("") == {}
    assert _auth_header("tok") == {"Authorization": "Bearer tok"}


def _capture() -> tuple[list[httpx.Headers], object]:
    """A MockTransport handler that records every request's headers."""
    seen: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(200, json=_OK)

    return seen, handler


@pytest.mark.asyncio
async def test_async_client_omits_auth_header_when_token_empty() -> None:
    """Both the auth-gated path (_rpc auth=True) and the unconditional path
    (_notify) must omit the header for an empty token."""
    seen, handler = _capture()
    hc = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = AsyncMCPClient("http://limenal", token_provider=lambda: "", http_client=hc)
    await client._rpc("tools/list", {}, auth=True)
    await client._notify("x/notify", {})
    await hc.aclose()

    assert len(seen) == 2
    assert all("authorization" not in h for h in seen)


@pytest.mark.asyncio
async def test_async_client_sends_auth_header_when_token_present() -> None:
    seen, handler = _capture()
    hc = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = AsyncMCPClient("http://limenal", token_provider=lambda: "tok-123", http_client=hc)
    await client._rpc("tools/list", {}, auth=True)
    await hc.aclose()

    assert seen[0]["authorization"] == "Bearer tok-123"


def test_sync_client_omits_auth_header_when_token_empty() -> None:
    seen, handler = _capture()
    hc = httpx.Client(transport=httpx.MockTransport(handler))
    client = MCPClient("http://limenal", token_provider=lambda: "", http_client=hc)
    client._rpc("tools/list", {}, auth=True)
    client._notify("x/notify", {})
    hc.close()

    assert len(seen) == 2
    assert all("authorization" not in h for h in seen)
