"""The Handler Protocol."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from liminal.protocol.context import Context
from liminal.protocol.tool import ToolResult, ToolSpec


@runtime_checkable
class Handler(Protocol):
    """Per-handler contract.

    A package implements this Protocol and exposes a `get_handler()`
    factory via the `liminal.handlers` entry-point group:

        # pyproject.toml of the handler package
        [project.entry-points."liminal.handlers"]
        slack = "my_handler_pkg.slack:get_handler"

    At liminal startup, the registry iterates the entry-point group,
    calls each factory, and registers the resulting Handler.
    """

    def tools(self) -> list[ToolSpec]:
        """Tools this handler provides."""
        ...

    def capability_card(self) -> dict[str, Any]:
        """Capability card as a plain dict; validated at registration time."""
        ...

    async def dispatch(
        self, name: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        """Invoke a named tool."""
        ...
