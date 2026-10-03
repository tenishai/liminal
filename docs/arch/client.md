---
card: arch-card:liminal-client
updated: 2026-10-03
anchor: src/liminal/client/mcp.py sha=041f2f934c7278e6f58bc79acc7430966c468880
anchor: src/liminal/client/library.py sha=bdd50eae29e0bb949cbe4b5d1d55c00fbdb2382f
---
# client — MCP client library other repos import

WHAT / SEAM: `liminal.client` (client/__init__.py). AsyncMCPClient / MCPClient (client/mcp.py): initialize, list_tools → list[Tool], call_tool(name, args, extra_headers=) → ToolCallOutcome(content, is_error, .text), ping, aclose (MCPClient, the sync twin, has `close`). Errors: MCPError base; MCPTransportError (network failure, 5xx, a body that is not a JSON object, or an event stream that ends without the reply) vs MCPRemoteError(code, message, data) (JSON-RPC error body; `code` is coerced to an int). DEFAULT_PROTOCOL_VERSION "2025-06-18". `LiminalClient` Protocol (client/protocol.py) unifies LibraryLiminalClient (in-process) and ProxyLiminalClient (HTTP wrapper of AsyncMCPClient); `from_config({"mode": "library"|"proxy", ...})` picks one.
OPS / FLOW: handshake auto-runs on first authenticated call; `token_provider` callable is invoked per request so short-lived JWTs refresh transparently. POSTs JSON-RPC to `<base_url>/mcp` with `Accept: application/json, text/event-stream`. If the server answers `text/event-stream` the client reads events until the one whose JSON-RPC `id` matches the request (notifications and server requests on the stream are skipped) and stops there without waiting for the stream to close (#129, #131); plain JSON replies work as before. `use_session=True` keeps the `Mcp-Session-Id` from `initialize` and sends it on later requests; it is OFF by default and HttpTarget does not enable it, because its client is shared across personas (#76, #129).
INVARIANTS:
- Library mode is "same process, same trust": it bypasses the HTTP route, so NO JWT, handler allowlist, scope gate, secret guard, or untrusted `_meta`. Use proxy mode wherever isolation matters.
- Library mode converts results with `to_spec_result_content` (the same function the HTTP route uses), so a `ToolResult.failure` message (`.error`) reaches the caller as text content alongside is_error=True (#66, #114). tests/test_liminal_client_protocol.py:test_library_failure_message_reaches_the_caller asserts it.
- Keep MCPTransportError vs MCPRemoteError distinct: HttpTarget maps them to different refusal reasons, and cabal catches by type.
CONSUMERS: cabal/src/cabal/core/tools/mcp_proxy.py (lazy `from liminal import client`; AsyncMCPClient, ToolCallOutcome); target/http.py (HttpTarget wraps AsyncMCPClient for upstreams). Tests: test_client.py, test_client_sse.py, test_liminal_client_protocol.py, test_client_auth_header_omitted.py.
API: exports LiminalClient, LibraryLiminalClient, ProxyLiminalClient, from_config, AsyncMCPClient, MCPClient, MCPError, MCPRemoteError, MCPTransportError, Tool, ToolCallOutcome.
