"""MCP client — minimal, library-grade.

Two flavors of the same surface:
  - `MCPClient` (sync) — wraps `httpx.Client`
  - `AsyncMCPClient` — wraps `httpx.AsyncClient`

Both expose the same three primary methods: `initialize`, `list_tools`,
`call_tool`. The handshake-on-first-call is automatic; callers can also
call `initialize` explicitly when they want to advertise capabilities.

The Bearer token is provided via a `token_provider` callable so callers
that mint short-lived JWTs can refresh transparently.
"""

from limenal.client.mcp import (
    AsyncMCPClient,
    MCPClient,
    MCPError,
    MCPRemoteError,
    MCPTransportError,
    Tool,
    ToolCallOutcome,
)

__all__ = [
    "AsyncMCPClient",
    "MCPClient",
    "MCPError",
    "MCPRemoteError",
    "MCPTransportError",
    "Tool",
    "ToolCallOutcome",
]
