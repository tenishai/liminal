"""LimenalClient Protocol — the contract for invoking limenal handlers.

Two impls, picked by config:

  Library mode (LibraryLimenalClient):
    In-process. Caller's Python imports limenal, gets a Registry, builds
    a Context, calls call_tool. No HTTP, no JWT enforcement — trust model
    is "same process, same trust boundary." Solo deployments, scripts,
    notebooks, embedded use.

  Proxy mode (ProxyLimenalClient):
    HTTP. Calls the limenal MCP server via JSON-RPC; the server enforces
    JWT auth + scope. Scale deployments, multi-tenant, anywhere process
    isolation matters.

Both implement the same surface: list_tools, call_tool, aclose. Caller
code is backend-agnostic; the mode is a deployment/config decision.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from limenal.client.mcp import Tool, ToolCallOutcome
from limenal.protocol.context import Context

__all__ = ["LimenalClient"]


@runtime_checkable
class LimenalClient(Protocol):
    """The contract every limenal client in cabal must satisfy.

    The Protocol is intentionally minimal — same three methods both
    AsyncMCPClient and InProcessDispatcher already expose, just unified
    under one name so callers don't care which is wired in.
    """

    async def list_tools(self) -> list[Tool]:
        """Return every tool available, namespaced by handler prefix."""
        ...

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        ctx: Context | None = None,
    ) -> ToolCallOutcome:
        """Invoke a tool. Returns the structured outcome.

        In library mode, `ctx` is constructed from caller-supplied
        identity/credentials (or a trusted-process default if omitted).
        In proxy mode, `ctx` is ignored — the HTTP request carries auth
        via the bearer JWT and the server builds Context server-side.
        """
        ...

    async def aclose(self) -> None:
        """Release any client-owned resources (HTTP pool, etc.). No-op
        in library mode."""
        ...
