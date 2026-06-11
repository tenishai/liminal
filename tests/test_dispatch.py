"""InProcessDispatcher tests."""

from __future__ import annotations

import pytest

from limenal.dispatch import DispatchError, InProcessDispatcher, UnknownTool
from limenal.protocol import Context, ToolResult, ToolSpec
from limenal.registry import Registry
from limenal.registry.discover import register_explicit


def _ctx() -> Context:
    return Context(identity="rook", agent_name="rook-primus", credentials={})


class _PingHandler:
    def tools(self) -> list[ToolSpec]:
        return [
            ToolSpec(name="ping", description="returns pong"),
            ToolSpec(name="echo", description="returns whatever you sent"),
        ]

    def capability_card(self) -> dict:
        return {
            "handler": "ping",
            "description": "test",
            "tools": [
                {"name": "ping", "description": "returns pong"},
                {"name": "echo", "description": "echoes payload"},
            ],
        }

    async def dispatch(self, name, payload, ctx):
        if name == "ping":
            return ToolResult.text("pong")
        if name == "echo":
            return ToolResult.json({"echoed": payload})
        return ToolResult.failure(f"unknown tool {name}")


class _RaiseHandler:
    def tools(self):
        return [ToolSpec(name="boom", description="raises")]

    def capability_card(self):
        return {"handler": "raise", "description": "raises", "tools": [{"name": "boom", "description": "raises"}]}

    async def dispatch(self, name, payload, ctx):
        raise RuntimeError("kaboom")


def _registry_with_ping() -> Registry:
    r = Registry()
    register_explicit(r, "ping", _PingHandler())
    return r


def test_list_tools_prefixes_with_handler_name() -> None:
    d = InProcessDispatcher(registry=_registry_with_ping())
    tools = d.list_tools()
    names = [t["name"] for t in tools]
    assert names == ["ping.ping", "ping.echo"]


@pytest.mark.asyncio
async def test_dispatch_happy_path() -> None:
    d = InProcessDispatcher(registry=_registry_with_ping())
    result = await d.dispatch(tool_name="ping.ping", payload={}, ctx=_ctx())
    assert result.is_error is False
    assert result.content[0]["text"] == "pong"


@pytest.mark.asyncio
async def test_dispatch_echo_carries_payload() -> None:
    d = InProcessDispatcher(registry=_registry_with_ping())
    result = await d.dispatch(
        tool_name="ping.echo", payload={"x": 42}, ctx=_ctx()
    )
    assert result.content[0]["data"]["echoed"] == {"x": 42}


@pytest.mark.asyncio
async def test_dispatch_unknown_handler_raises() -> None:
    d = InProcessDispatcher(registry=_registry_with_ping())
    with pytest.raises(UnknownTool):
        await d.dispatch(tool_name="ghost.x", payload={}, ctx=_ctx())


@pytest.mark.asyncio
async def test_dispatch_unprefixed_tool_raises() -> None:
    d = InProcessDispatcher(registry=_registry_with_ping())
    with pytest.raises(DispatchError):
        await d.dispatch(tool_name="ping", payload={}, ctx=_ctx())


@pytest.mark.asyncio
async def test_handler_exception_becomes_tool_result_failure() -> None:
    """A raise inside the handler should NOT propagate — should become a
    structured ToolResult.failure so the agent sees a tool-level error."""
    r = Registry()
    register_explicit(r, "raise", _RaiseHandler())
    d = InProcessDispatcher(registry=r)
    result = await d.dispatch(tool_name="raise.boom", payload={}, ctx=_ctx())
    assert result.is_error is True
    assert "kaboom" in result.error
