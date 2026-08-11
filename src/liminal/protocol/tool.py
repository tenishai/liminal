"""Tool spec + tool result types.

These mirror MCP's `Tool` and tool-call result shape closely enough that
liminal can forward them onto the wire without rewriting structure, while
keeping the Python surface ergonomic for handler authors.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Open(BaseModel):
    model_config = ConfigDict(extra="allow")


class ToolSpec(_Open):
    """A single tool exposed by a handler.

    `input_schema` is a JSON Schema describing the call payload; agents
    use it to decide how to fill arguments. liminal does NOT validate
    payloads against it by default — that's the handler's job — but
    `validate_input` will if a handler opts in.
    """

    name: str
    description: str
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}}
    )


class ToolResult(_Open):
    """Wraps a handler's return value with success / error structure.

    Errors that the agent can act on (rate-limited, quarantined, permission
    denied) belong here. Truly exceptional handler-internal failures should
    raise — liminal's dispatch layer catches and converts to a ToolResult
    with `error`.
    """

    content: list[dict[str, Any]] = Field(default_factory=list)
    is_error: bool = False
    error: str | None = None

    @classmethod
    def text(cls, text: str) -> ToolResult:
        """Build a successful text result."""
        return cls(content=[{"type": "text", "text": text}])

    @classmethod
    def json(cls, payload: dict[str, Any]) -> ToolResult:
        """Build a successful structured result wrapped in MCP's content shape."""
        return cls(content=[{"type": "json", "data": payload}])

    @classmethod
    def failure(cls, message: str) -> ToolResult:
        return cls(is_error=True, error=message, content=[])
