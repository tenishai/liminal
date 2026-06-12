"""ProxyLimenalClient — HTTP LimenalClient impl.

Wraps the existing AsyncMCPClient with a Protocol-conforming surface.
JWT-authenticated, HTTP-based; the limenal server enforces auth + scope
at the route layer. Same behavior as today; the rename + class exposes
the dual-mode design explicitly.

AsyncMCPClient stays public for backward compat — anything that already
imports it keeps working.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx

from limenal.client.mcp import AsyncMCPClient, Tool, ToolCallOutcome
from limenal.protocol.context import Context

__all__ = ["ProxyLimenalClient"]


class ProxyLimenalClient:
    """HTTP LimenalClient — forwards calls to a remote limenal MCP server."""

    def __init__(
        self,
        base_url: str,
        *,
        token_provider: Callable[[], str],
        http_client: httpx.AsyncClient | None = None,
        client_name: str = "limenal-client",
    ) -> None:
        self._inner = AsyncMCPClient(
            base_url=base_url,
            token_provider=token_provider,
            http_client=http_client,
            client_name=client_name,
        )

    async def list_tools(self) -> list[Tool]:
        return await self._inner.list_tools()

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        ctx: Context | None = None,
    ) -> ToolCallOutcome:
        """Forward via HTTP. `ctx` is intentionally ignored — auth and
        identity flow through the JWT in the bearer token; the limenal
        server constructs the Context on its side."""
        return await self._inner.call_tool(name, arguments)

    async def aclose(self) -> None:
        await self._inner.aclose()

    @property
    def server_capabilities(self) -> dict[str, Any]:
        """Expose underlying capabilities for callers that need them."""
        return self._inner.server_capabilities
