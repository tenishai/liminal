"""scratchpad handler — end-to-end behavior through the dispatcher."""

from __future__ import annotations

import pytest

from liminal.dispatch import InProcessDispatcher
from liminal.handlers.scratchpad import ScratchpadHandler
from liminal.protocol import Context
from liminal.registry import Registry
from liminal.registry.discover import register_explicit


def _dispatcher() -> InProcessDispatcher:
    r = Registry()
    # Fresh instance per-test so process-local state doesn't leak
    register_explicit(r, "scratchpad", ScratchpadHandler())
    return InProcessDispatcher(registry=r)


def _ctx(agent: str = "rook-primus", identity: str = "rook") -> Context:
    return Context(identity=identity, agent_name=agent, credentials={})


@pytest.mark.asyncio
async def test_set_then_get() -> None:
    d = _dispatcher()
    await d.dispatch(
        tool_name="scratchpad.set",
        payload={"key": "favorite_color", "value": "blue"},
        ctx=_ctx(),
    )
    result = await d.dispatch(
        tool_name="scratchpad.get",
        payload={"key": "favorite_color"},
        ctx=_ctx(),
    )
    assert result.content[0]["data"]["value"] == "blue"


@pytest.mark.asyncio
async def test_get_missing_returns_null() -> None:
    d = _dispatcher()
    result = await d.dispatch(
        tool_name="scratchpad.get", payload={"key": "ghost"}, ctx=_ctx()
    )
    assert result.content[0]["data"]["value"] is None


@pytest.mark.asyncio
async def test_list_returns_sorted_keys() -> None:
    d = _dispatcher()
    await d.dispatch(
        tool_name="scratchpad.set", payload={"key": "b", "value": 1}, ctx=_ctx()
    )
    await d.dispatch(
        tool_name="scratchpad.set", payload={"key": "a", "value": 1}, ctx=_ctx()
    )
    result = await d.dispatch(
        tool_name="scratchpad.list", payload={}, ctx=_ctx()
    )
    assert result.content[0]["data"]["keys"] == ["a", "b"]


@pytest.mark.asyncio
async def test_clear_wipes_keys() -> None:
    d = _dispatcher()
    await d.dispatch(
        tool_name="scratchpad.set", payload={"key": "x", "value": 1}, ctx=_ctx()
    )
    await d.dispatch(tool_name="scratchpad.clear", payload={}, ctx=_ctx())
    listing = await d.dispatch(
        tool_name="scratchpad.list", payload={}, ctx=_ctx()
    )
    assert listing.content[0]["data"]["keys"] == []


@pytest.mark.asyncio
async def test_per_agent_isolation() -> None:
    """Two agents under the same identity should NOT see each other's notes."""
    d = _dispatcher()
    await d.dispatch(
        tool_name="scratchpad.set",
        payload={"key": "secret", "value": "primus-only"},
        ctx=_ctx("rook-primus"),
    )
    result = await d.dispatch(
        tool_name="scratchpad.get",
        payload={"key": "secret"},
        ctx=_ctx("rook-secundus"),
    )
    assert result.content[0]["data"]["value"] is None


@pytest.mark.asyncio
async def test_per_identity_isolation() -> None:
    """Two agents under different identities (rook vs raven) are isolated."""
    d = _dispatcher()
    await d.dispatch(
        tool_name="scratchpad.set",
        payload={"key": "k", "value": "rook"},
        ctx=_ctx("primus", identity="rook"),
    )
    result = await d.dispatch(
        tool_name="scratchpad.get",
        payload={"key": "k"},
        ctx=_ctx("primus", identity="raven"),
    )
    assert result.content[0]["data"]["value"] is None


@pytest.mark.asyncio
async def test_set_requires_non_empty_key() -> None:
    d = _dispatcher()
    result = await d.dispatch(
        tool_name="scratchpad.set",
        payload={"key": "", "value": "x"},
        ctx=_ctx(),
    )
    assert result.is_error is True


@pytest.mark.asyncio
async def test_unknown_tool_returns_failure() -> None:
    d = _dispatcher()
    result = await d.dispatch(
        tool_name="scratchpad.banish", payload={}, ctx=_ctx()
    )
    assert result.is_error is True
    assert "banish" in result.error
