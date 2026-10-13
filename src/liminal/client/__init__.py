"""MCP client — minimal, library-grade.

Two flavors of the same surface:
  - `MCPClient` (sync) — wraps `httpx.Client`
  - `AsyncMCPClient` — wraps `httpx.AsyncClient`

Both expose the same three primary methods: `initialize`, `list_tools`,
`call_tool`. The handshake-on-first-call is automatic; callers can also
call `initialize` explicitly when they want to advertise capabilities.

The credential is provided via a `token_provider` callable so callers
that mint short-lived JWTs can refresh transparently. It goes out as
`Bearer <token>` by default, or as `Basic base64(<token>)` with
`auth_scheme="basic"`.
"""

from liminal.client.factory import from_config
from liminal.client.library import LibraryLiminalClient
from liminal.client.mcp import (
    AsyncMCPClient,
    MCPClient,
    MCPError,
    MCPRemoteError,
    MCPTransportError,
    Tool,
    ToolCallOutcome,
)
from liminal.client.protocol import LiminalClient
from liminal.client.proxy import ProxyLiminalClient

__all__ = [
    # Protocol + impls (preferred surface)
    "LiminalClient",
    "LibraryLiminalClient",
    "ProxyLiminalClient",
    "from_config",
    # MCP client (backward-compat; AsyncMCPClient is what ProxyLiminalClient wraps)
    "AsyncMCPClient",
    "MCPClient",
    "MCPError",
    "MCPRemoteError",
    "MCPTransportError",
    "Tool",
    "ToolCallOutcome",
]
