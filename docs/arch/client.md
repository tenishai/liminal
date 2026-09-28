---
card: arch-card:liminal-client
updated: 2026-09-28
anchor: src/liminal/client/mcp.py sha=e804cf4cbfbafb2411ec65aabbe9e5ce4d2eb177
anchor: src/liminal/client/library.py sha=c026456bb9adb3e02b0c842ba4a0e88944c6d5dc
---
# client — MCP client library other repos import

WHAT / SEAM: `liminal.client` (client/__init__.py). AsyncMCPClient / MCPClient (client/mcp.py): initialize, list_tools → list[Tool], call_tool(name, args, extra_headers=) → ToolCallOutcome(content, is_error, .text), ping, aclose. Errors: MCPError base; MCPTransportError (network/HTTP) vs MCPRemoteError(code, message, data) (JSON-RPC error body). DEFAULT_PROTOCOL_VERSION "2025-06-18". `LiminalClient` Protocol (client/protocol.py) unifies LibraryLiminalClient (in-process) and ProxyLiminalClient (HTTP wrapper of AsyncMCPClient); `from_config({"mode": "library"|"proxy", ...})` picks one.
OPS / FLOW: handshake auto-runs on first authenticated call; `token_provider` callable is invoked per request so short-lived JWTs refresh transparently. POSTs JSON-RPC to `<base_url>/mcp`.
INVARIANTS:
- Library mode is "same process, same trust": it bypasses the HTTP route, so NO JWT, handler allowlist, scope gate, secret guard, or untrusted `_meta`. Use proxy mode wherever isolation matters.
- Library mode converts results with `to_spec_content`, not `to_spec_result_content`, so a `ToolResult.failure` message (`.error`) is DROPPED: caller gets is_error=True with empty content. The HTTP route appends it (#66). (observed in code; no test asserts either way — unverified whether intended)
- Keep MCPTransportError vs MCPRemoteError distinct: HttpTarget maps them to different refusal reasons, and cabal catches by type.
CONSUMERS: cabal/src/cabal/core/tools/mcp_proxy.py (lazy `from liminal import client`; AsyncMCPClient, ToolCallOutcome); target/http.py (HttpTarget wraps AsyncMCPClient for upstreams). Tests: test_client.py, test_liminal_client_protocol.py, test_client_auth_header_omitted.py.
API: exports LiminalClient, LibraryLiminalClient, ProxyLiminalClient, from_config, AsyncMCPClient, MCPClient, MCPError, MCPRemoteError, MCPTransportError, Tool, ToolCallOutcome.
