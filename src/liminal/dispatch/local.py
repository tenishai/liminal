"""In-process dispatch — solo mode.

Resolve `tool_name` (which arrives prefixed with the handler name, e.g.
`slack.send_message`) to a registered Handler, then await its `dispatch()`.

Exceptions raised inside a handler are caught and converted into
ToolResult.failure so the caller (the agent) always sees a structured
result. The QUARANTINED state from design.md §"Crash-loop protection" is
scale-mode-only; in solo mode a raise is just a tool-call error.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

import structlog

from liminal.protocol import Context, ToolResult
from liminal.registry import Registry

log = structlog.get_logger(__name__)

TOOL_NAME_SEPARATOR = "."


class DispatchError(RuntimeError):
    """Dispatch failed at the routing layer (bad tool name, unknown handler).

    Raised when the caller's request is malformed enough that there's no
    handler to even attempt — these become MCP-level errors. Once a
    handler is selected, internal failures become ToolResult.failure
    instead.
    """


class UnknownTool(DispatchError):
    """No registered handler matches the prefix in tool_name."""


@dataclass(slots=True)
class InProcessDispatcher:
    """Resolves a tool_name to a Handler and invokes it."""

    registry: Registry

    def list_tools(self) -> list[dict[str, Any]]:
        """All tools across all registered handlers, prefixed with handler
        name so callers can distinguish e.g. `slack.send_message` from
        `email.send_message`."""
        out: list[dict[str, Any]] = []
        for record in self.registry:
            for tool in record.handler.tools():
                spec = tool.model_dump(by_alias=True)
                spec["name"] = f"{record.name}{TOOL_NAME_SEPARATOR}{tool.name}"
                out.append(spec)
        return out

    async def dispatch(
        self,
        *,
        tool_name: str,
        payload: dict[str, Any],
        ctx: Context,
    ) -> ToolResult:
        handler_name, _, local_name = tool_name.partition(TOOL_NAME_SEPARATOR)
        if not local_name:
            raise DispatchError(
                f"tool name {tool_name!r} must be prefixed with handler "
                f"name (e.g., 'scratchpad.set')"
            )
        record = self.registry.get(handler_name)
        if record is None:
            raise UnknownTool(
                f"no handler registered for prefix {handler_name!r}"
            )
        try:
            return await record.handler.dispatch(local_name, payload, ctx)
        except Exception as exc:  # noqa: BLE001
            return raised_failure(
                "dispatch.handler_raised",
                f"{handler_name}.{local_name}",
                exc,
                handler=handler_name,
                tool=local_name,
            )


def raised_failure(
    event: str, tool_name: str, exc: Exception, **fields: Any
) -> ToolResult:
    """Log a handler's exception and return the failure the caller sees.

    The caller gets the tool name, the exception class and a short error id;
    the log line gets the same id plus the exception's message. The message
    stays out of the result because it can carry paths, upstream text or
    other detail the agent should not see; the id is how an operator joins
    the agent's report to the log line (#193). Shared by the Multiplexer and
    InProcessDispatcher so both produce the same text.
    """
    error_id = uuid.uuid4().hex[:8]
    log.warning(
        event,
        error_id=error_id,
        error_type=type(exc).__name__,
        error=str(exc),
        **fields,
    )
    return ToolResult.failure(
        f"{tool_name} raised {type(exc).__name__} (error id {error_id})"
    )
