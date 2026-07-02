"""MCP HTTP server.

The agent-facing wire transport. JSON-RPC 2.0 over POST /mcp, with optional
SSE response when a single call wants to stream chunks back.

Authentication is pluggable: a `JWTVerifier` instance decides what counts
as a valid bearer. The built-in implementations verify against a static
KeySet (tests) or a remote JWKS URL (production, e.g. Cabal Core).
"""

from limenal.server.admin import build_admin_router
from limenal.server.app import create_app
from limenal.server.auth import (
    AuthError,
    IssuerConfig,
    JWTVerifier,
    MultiIssuerJWKSVerifier,
    StaticKeySetVerifier,
    URLJWKSVerifier,
    VerifiedClaims,
    build_multi_issuer_verifier,
)
from limenal.server.credentials import (
    CabalCoreCredentialResolver,
    CredentialResolver,
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
from limenal.server.policy import (
    AuditRow,
    GrantRow,
    ParentImmutable,
    PolicyStore,
    ScopeGrant,
    SqlitePolicyStore,
)

__all__ = [
    "AuditRow",
    "AuthError",
    "CabalCoreCredentialResolver",
    "CredentialResolver",
    "GrantRow",
    "InitializeParams",
    "InitializeResult",
    "IssuerConfig",
    "JSONRPCError",
    "JSONRPCRequest",
    "JSONRPCResponse",
    "JWTVerifier",
    "MultiIssuerJWKSVerifier",
    "ParentImmutable",
    "PolicyStore",
    "ScopeGrant",
    "SqlitePolicyStore",
    "StaticKeySetVerifier",
    "ToolCallParams",
    "ToolCallResult",
    "ToolsListResult",
    "URLJWKSVerifier",
    "VerifiedClaims",
    "build_admin_router",
    "build_multi_issuer_verifier",
    "create_app",
]
