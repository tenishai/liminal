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

from limenal.client.factory import from_config
from limenal.client.library import LibraryLimenalClient
from limenal.client.mcp import (
    AsyncMCPClient,
    MCPClient,
    MCPError,
    MCPRemoteError,
    MCPTransportError,
    Tool,
    ToolCallOutcome,
)
from limenal.client.protocol import LimenalClient
from limenal.client.proxy import ProxyLimenalClient

__all__ = [
    # Protocol + impls (preferred surface)
    "LimenalClient",
    "LibraryLimenalClient",
    "ProxyLimenalClient",
    "from_config",
    # MCP client (backward-compat; AsyncMCPClient is what ProxyLimenalClient wraps)
    "AsyncMCPClient",
    "MCPClient",
    "MCPError",
    "MCPRemoteError",
    "MCPTransportError",
    "Tool",
    "ToolCallOutcome",
]
