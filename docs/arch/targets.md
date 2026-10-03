---
card: arch-card:liminal-targets
updated: 2026-10-03
anchor: src/liminal/dispatch/multiplexer.py sha=26f5e3dabc7105cfae322b1d9ba20ad92fb183e0
anchor: src/liminal/target/http.py sha=fc7a849e47ffd10c97fb421aec5e40e775d8eb68
anchor: src/liminal/target/config.py sha=f9b8ef86b694427754623478e9b4827232a936ff
anchor: src/liminal/target/inspect.py sha=ac28df939b131dac9756622c02e0a78a98ea15a0
---
# targets — Multiplexer + federated MCP upstreams

WHAT / SEAM: `Target` Protocol (target/base.py): name, trust (TrustTier TRUSTED|UNTRUSTED), startup/shutdown, async list_tools (UNprefixed), dispatch(tool, payload, ctx), protocol_version. Impls: InProcessTarget (wraps a Handler, always TRUSTED), HttpTarget (one HTTP MCP upstream via AsyncMCPClient; an upstream that replies with SSE is read by the client, #131). `Multiplexer` (dispatch/multiplexer.py) holds targets by name, prefixes `{name}.{tool}`, routes by `partition(".")`. InProcessDispatcher (dispatch/local.py) is the older registry-only twin, still used by LibraryLiminalClient.
CONFIG: `liminal serve --targets targets.toml` → `[[target]]` tables → `TargetSpec` (target/config.py): name, transport http|stdio, command (stdio argv, required for stdio), address (base URL WITHOUT /mcp; client appends it, #69), trust (default untrusted), on_untrusted flag|strip|block, identity forward|none, auth_method bearer|service-token|none, bearer_token (required when auth_method=bearer), credential_key, client_name, required_scope, tool_scopes, headers (static request headers, http only), timeouts, refresh interval (300s). An unknown `[[target]]` key is a TargetConfigError, which includes `relevance_signals` (removed, #136).
OPS / FLOW: lifespan → Multiplexer.startup → HttpTarget connects, initializes, fetches catalog → `inspect_catalog` (target/inspect.py) scans UNTRUSTED catalogs for override phrases, hidden/bidi unicode, >1024-char descriptions, schema >10k nodes or >64 deep → applies on_untrusted. Background refresh re-fetches. Dispatch → per-call headers (`x-liminal-persona`, `x-liminal-issuer` if identity=forward; `Authorization` from ctx.credentials if service-token; `x-correlation-id` always) → upstream → UNTRUSTED results wrapped by `frame_untrusted_result` (nonce-tagged banner, hidden unicode stripped from every string, to depth `MAX_CONTENT_DEPTH` = 64 in inspect.py; deeper content raises UnsanitizableResult, which becomes a refusal) and flagged `liminal_untrusted*` → routes.py copies to `_meta`.
INVARIANTS:
- `tool_name.split(".",1)[0] == target.name == registry key` is the authz key for allowlist, scope map and credentials. Guarded by tests/test_dispatch_contract.py. Target names: non-empty, no `.`, no collision with handlers or each other (TargetConfigError).
- `headers` (#130, #135): http only (a stdio spec with headers is refused); values must be strings; names are case-insensitive and two names differing only by case are refused; any name in `RESERVED_HEADERS` (target/config.py: authorization, x-liminal-persona, x-liminal-issuer, x-correlation-id, mcp-session-id, accept, content-type) is refused. HttpTarget passes them to its AsyncMCPClient as `static_headers`, so they ride `initialize`, catalog fetch and every call, and the client's own headers win a collision.
- Only `transport="http"` is served; stdio specs validate but build_http_targets rejects them ("Stage A"). stdio + identity forwarding is rejected at config time (children cannot carry per-request identity).
- Per-call headers are built fresh and NEVER stored on the shared client (#13), so persona A's token cannot ride persona B's request. The shared client also keeps `use_session` off, so an upstream `Mcp-Session-Id` from the base handshake is never echoed on a persona's call (#129; tests/test_http_target.py).
- Missing or whitespace-only service-token credential → refusal ToolResult, never an unauthenticated upstream call (#80).
- One target's startup failure does not stop the others (#86); it stays registered and /healthz reports `degraded` with one of "startup failed", "catalog fetch failed (startup|refresh)", "catalog inspection failed (startup|refresh)" or "not started". A failed catalog = zero tools, visible on /healthz (#75).
- Consumers must trust `_meta["liminal/untrusted"]` + nonce, not the banner text (an upstream can imitate text).
- Unsanitizable upstream content → refusal ToolResult naming target and cause, not an exception.
- Owned httpx client rejects all cookies (#76).
- Target scopes are operator config only (see policy.md); declaring tool_scopes makes the target deny-by-default.
CONSUMERS: server/app.py:create_app (builds all targets), server/routes.py (dispatch, /healthz, `_meta`). Tests: test_http_target.py, test_untrusted_result_framing.py, test_catalog_depth_bound.py, test_cli_targets.py, test_tool_extras_forwarding.py.
API: `liminal.target` exports HttpTarget, InProcessTarget, Target, TargetConfigError, TargetSpec, TrustTier, build_http_targets, inspect_catalog, load_target_specs, scan_tool; `liminal.dispatch` exports Multiplexer, InProcessDispatcher, DispatchError, UnknownTool.
