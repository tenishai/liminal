"""LimenalClient Protocol tests.

The same test surface runs against both LibraryLimenalClient (in-process
dispatch) and ProxyLimenalClient (HTTP to a real ASGI-mounted limenal
server). If the two ever drift on the visible surface, these tests fail.
"""

from __future__ import annotations

import httpx
import pytest
from httpx import ASGITransport

from limenal.client import (
    LibraryLimenalClient,
    LimenalClient,
    ProxyLimenalClient,
    from_config,
)
from limenal.handlers.scratchpad import ScratchpadHandler
from limenal.registry import Registry
from limenal.registry.discover import register_explicit


@pytest.fixture
def registry() -> Registry:
    r = Registry()
    register_explicit(r, "scratchpad", ScratchpadHandler())
    return r


@pytest.fixture
def library_client(registry) -> LibraryLimenalClient:
    return LibraryLimenalClient(registry=registry)


@pytest.fixture
async def proxy_client(app, mint_token):
    """ProxyLimenalClient pointed at an in-process limenal ASGI app."""
    transport = ASGITransport(app=app)
    http = httpx.AsyncClient(transport=transport, base_url="http://test")
    client = ProxyLimenalClient(
        base_url="http://test",
        token_provider=lambda: mint_token(persona="rook", sub="rook-primus"),
        http_client=http,
    )
    yield client
    await client.aclose()


# ---- Protocol satisfaction -------------------------------------------------


def test_library_client_satisfies_protocol(library_client) -> None:
    assert isinstance(library_client, LimenalClient)


def test_proxy_client_satisfies_protocol() -> None:
    """Construct a ProxyLimenalClient without a network connection just to
    check isinstance — no calls are made."""
    client = ProxyLimenalClient(
        base_url="http://test",
        token_provider=lambda: "stub-token",
    )
    assert isinstance(client, LimenalClient)


# ---- LibraryLimenalClient: in-process roundtrips ---------------------------


@pytest.mark.asyncio
async def test_library_list_tools_returns_namespaced(library_client) -> None:
    tools = await library_client.list_tools()
    names = {t.name for t in tools}
    assert "scratchpad.set" in names
    assert "scratchpad.get" in names


@pytest.mark.asyncio
async def test_library_call_tool_roundtrip(library_client) -> None:
    await library_client.call_tool(
        "scratchpad.set", {"key": "color", "value": "purple"}
    )
    outcome = await library_client.call_tool("scratchpad.get", {"key": "color"})
    assert outcome.is_error is False
    import json
    assert json.loads(outcome.content[0]["text"])["value"] == "purple"


@pytest.mark.asyncio
async def test_library_aclose_is_idempotent(library_client) -> None:
    await library_client.aclose()
    await library_client.aclose()  # no error


@pytest.mark.asyncio
async def test_library_default_ctx_when_none_passed(registry) -> None:
    """When caller doesn't pass ctx, default identity is used so
    scratchpad's per-(identity, agent) isolation still applies."""
    client = LibraryLimenalClient(
        registry=registry,
        default_identity="alpha",
        default_agent_name="alpha-1",
    )
    await client.call_tool("scratchpad.set", {"key": "k", "value": "alpha-value"})

    other = LibraryLimenalClient(
        registry=registry,
        default_identity="beta",
        default_agent_name="beta-1",
    )
    outcome = await other.call_tool("scratchpad.get", {"key": "k"})
    import json
    assert json.loads(outcome.content[0]["text"])["value"] is None


@pytest.mark.asyncio
async def test_library_credential_resolver_invoked(registry) -> None:
    """When a credential_resolver is wired, it's called per-dispatch."""
    seen: list[tuple[str, str]] = []

    async def resolver(identity: str, handler: str) -> dict[str, str]:
        seen.append((identity, handler))
        return {"FAKE_KEY": "val"}

    client = LibraryLimenalClient(
        registry=registry,
        default_identity="rook",
        default_agent_name="rook-primus",
        credential_resolver=resolver,
    )
    await client.call_tool("scratchpad.set", {"key": "k", "value": "v"})
    assert seen == [("rook", "scratchpad")]


# ---- ProxyLimenalClient: HTTP roundtrips (against ASGI-mounted app) --------


@pytest.mark.asyncio
async def test_proxy_list_tools_via_http(proxy_client) -> None:
    tools = await proxy_client.list_tools()
    names = {t.name for t in tools}
    assert "scratchpad.set" in names


@pytest.mark.asyncio
async def test_proxy_call_tool_via_http(proxy_client) -> None:
    await proxy_client.call_tool(
        "scratchpad.set", {"key": "color", "value": "indigo"}
    )
    outcome = await proxy_client.call_tool("scratchpad.get", {"key": "color"})
    assert outcome.is_error is False
    import json
    assert json.loads(outcome.content[0]["text"])["value"] == "indigo"


# ---- factory ---------------------------------------------------------------


def test_factory_library_mode(registry) -> None:
    client = from_config({"mode": "library", "registry": registry})
    assert isinstance(client, LibraryLimenalClient)


def test_factory_proxy_mode() -> None:
    client = from_config({
        "mode": "proxy",
        "url": "http://test",
        "token_provider": lambda: "tok",
    })
    assert isinstance(client, ProxyLimenalClient)


def test_factory_rejects_unknown_mode() -> None:
    with pytest.raises(ValueError, match="unknown LimenalClient mode"):
        from_config({"mode": "what"})


def test_factory_rejects_proxy_without_url() -> None:
    with pytest.raises(ValueError, match="proxy mode requires 'url'"):
        from_config({"mode": "proxy", "token_provider": lambda: "tok"})
