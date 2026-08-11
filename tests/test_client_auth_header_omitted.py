"""liminal#32 — the MCP client OMITS the Authorization header entirely when the
token_provider returns an empty string (the natural thing in a no-auth
deployment, ``LIMINAL_AUTH_DISABLED=1``), instead of emitting ``Bearer `` — an
empty value httpx rejects as an illegal header before the request leaves the
client.

The original bug hid behind green in-process tests because ``httpx.ASGITransport``
does NOT enforce header legality (the real-network rejection lives in the h11
layer, which both ASGITransport and MockTransport bypass). So these tests do NOT
rely on any transport rejecting the header — they use ``httpx.MockTransport``
purely to CAPTURE the exact headers the client sets on each request and assert
on their presence/absence directly.
"""

from __future__ import annotations

import httpx
import pytest

from liminal.client.mcp import AsyncMCPClient, MCPClient, _auth_header

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
    client = AsyncMCPClient("http://liminal", token_provider=lambda: "", http_client=hc)
    await client._rpc("tools/list", {}, auth=True)
    await client._notify("x/notify", {})
    await hc.aclose()

    assert len(seen) == 2
    assert all("authorization" not in h for h in seen)


@pytest.mark.asyncio
async def test_async_client_sends_auth_header_when_token_present() -> None:
    seen, handler = _capture()
    hc = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = AsyncMCPClient("http://liminal", token_provider=lambda: "tok-123", http_client=hc)
    await client._rpc("tools/list", {}, auth=True)
    await hc.aclose()

    assert seen[0]["authorization"] == "Bearer tok-123"


def test_sync_client_omits_auth_header_when_token_empty() -> None:
    seen, handler = _capture()
    hc = httpx.Client(transport=httpx.MockTransport(handler))
    client = MCPClient("http://liminal", token_provider=lambda: "", http_client=hc)
    client._rpc("tools/list", {}, auth=True)
    client._notify("x/notify", {})
    hc.close()

    assert len(seen) == 2
    assert all("authorization" not in h for h in seen)


def test_sync_client_sends_auth_header_when_token_present() -> None:
    seen, handler = _capture()
    hc = httpx.Client(transport=httpx.MockTransport(handler))
    client = MCPClient("http://liminal", token_provider=lambda: "tok-123", http_client=hc)
    client._rpc("tools/list", {}, auth=True)
    hc.close()

    assert seen[0]["authorization"] == "Bearer tok-123"
