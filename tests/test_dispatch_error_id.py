"""A handler's exception reaches the agent with an error id, not its message.

#193: the agent used to get only "<target>.<tool> raised <Class>", and the
operator had to match it to the log line by timestamp. Both dispatchers now
put a short id in the failure text and on the log line, and keep the
exception's message (which can carry paths or upstream text) in the log.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
import structlog

from liminal.dispatch import InProcessDispatcher, Multiplexer
from liminal.protocol import Context, ToolResult, ToolSpec
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.target.inprocess import InProcessTarget

SECRET = "/home/op/secret-path leaked detail"
FAILURE_RE = re.compile(r"^boom\.explode raised ValueError \(error id ([0-9a-f]{8})\)$")


class _Boom:
    def tools(self) -> list[ToolSpec]:
        return [ToolSpec(name="explode", description="raises", input_schema={"type": "object"})]

    def capability_card(self) -> dict[str, Any]:
        return {"handler": "boom", "description": "always raises", "tools": []}

    async def dispatch(self, name: str, payload: dict[str, Any], ctx: Context) -> ToolResult:
        raise ValueError(SECRET)


def _ctx() -> Context:
    return Context(identity="rook", agent_name="rook-primus", credentials={}, extra={})


def _multiplexer() -> Multiplexer:
    return Multiplexer([InProcessTarget(name="boom", handler=_Boom())])


def _in_process() -> InProcessDispatcher:
    registry = Registry()
    register_explicit(registry, "boom", _Boom())
    return InProcessDispatcher(registry=registry)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("make", "event"),
    [
        (_multiplexer, "multiplexer.target_raised"),
        (_in_process, "dispatch.handler_raised"),
    ],
)
async def test_failure_and_log_line_share_an_error_id(make: Any, event: str) -> None:
    dispatcher = make()
    with structlog.testing.capture_logs() as logs:
        result = await dispatcher.dispatch(
            tool_name="boom.explode", payload={}, ctx=_ctx()
        )
    assert result.is_error is True
    match = FAILURE_RE.match(result.error or "")
    assert match is not None, result.error
    error_id = match.group(1)

    raised = [entry for entry in logs if entry["event"] == event]
    assert len(raised) == 1
    assert raised[0]["error_id"] == error_id
    assert raised[0]["error"] == SECRET
    assert raised[0]["error_type"] == "ValueError"


@pytest.mark.asyncio
@pytest.mark.parametrize("make", [_multiplexer, _in_process])
async def test_exception_message_stays_out_of_the_failure(make: Any) -> None:
    result = await make().dispatch(tool_name="boom.explode", payload={}, ctx=_ctx())
    assert "secret-path" not in (result.error or "")


@pytest.mark.asyncio
async def test_each_failure_gets_its_own_error_id() -> None:
    dispatcher = _multiplexer()
    ids = set()
    for _ in range(5):
        result = await dispatcher.dispatch(tool_name="boom.explode", payload={}, ctx=_ctx())
        match = FAILURE_RE.match(result.error or "")
        assert match is not None, result.error
        ids.add(match.group(1))
    assert len(ids) == 5
