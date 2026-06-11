"""MCP HTTP server.

The agent-facing wire transport. JSON-RPC 2.0 over POST /mcp, with optional
SSE response when a single call wants to stream chunks back.

Authentication is pluggable: a `JWTVerifier` instance decides what counts
as a valid bearer. The built-in implementations verify against a static
KeySet (tests) or a remote JWKS URL (production, e.g. Cabal Core).
"""

from limenal.server.app import create_app
from limenal.server.auth import (
    AuthError,
    JWTVerifier,
    StaticKeySetVerifier,
    URLJWKSVerifier,
)
from limenal.server.mcp_types import (
    InitializeParams,
    InitializeResult,
    JSONRPCError,
    JSONRPCRequest,
    JSONRPCResponse,
    ToolCallParams,
    ToolCallResult,
    ToolsListResult,
)

__all__ = [
    "AuthError",
    "InitializeParams",
    "InitializeResult",
    "JSONRPCError",
    "JSONRPCRequest",
    "JSONRPCResponse",
    "JWTVerifier",
    "StaticKeySetVerifier",
    "ToolCallParams",
    "ToolCallResult",
    "ToolsListResult",
    "URLJWKSVerifier",
    "create_app",
]
