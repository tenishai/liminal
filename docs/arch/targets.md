---
card: arch-card:liminal-targets
updated: 2026-09-28
anchor: src/liminal/dispatch/multiplexer.py sha=26f5e3dabc7105cfae322b1d9ba20ad92fb183e0
anchor: src/liminal/target/http.py sha=a18462f473881f8784a7d6b6471cdc7232e63b0a
anchor: src/liminal/target/config.py sha=b8d757725837b954b3c87a886bbef30f06031c7f
anchor: src/liminal/target/inspect.py sha=ac28df939b131dac9756622c02e0a78a98ea15a0
---
# targets — Multiplexer + federated MCP upstreams

WHAT / SEAM: `Target` Protocol (target/base.py): name, trust (TrustTier TRUSTED|UNTRUSTED), startup/shutdown, async list_tools (UNprefixed), dispatch(tool, payload, ctx), protocol_version. Impls: InProcessTarget (wraps a Handler, always TRUSTED), HttpTarget (one HTTP MCP upstream via AsyncMCPClient). `Multiplexer` (dispatch/multiplexer.py) holds targets by name, prefixes `{name}.{tool}`, routes by `partition(".")`. InProcessDispatcher (dispatch/local.py) is the older registry-only twin, still used by LibraryLiminalClient.
CONFIG: `liminal serve --targets targets.toml` → `[[target]]` tables → `TargetSpec` (target/config.py): name, transport http|stdio, address (base URL WITHOUT /mcp; client appends it, #69), trust (default untrusted), on_untrusted flag|strip|block, identity forward|none, auth_method bearer|service-token|none, credential_key, required_scope, tool_scopes, timeouts, refresh interval (300s).
OPS / FLOW: lifespan → Multiplexer.startup → HttpTarget connects, initializes, fetches catalog → `inspect_catalog` (target/inspect.py) scans UNTRUSTED catalogs for override phrases, hidden/bidi unicode, >1024-char descriptions, schema >10k nodes or >64 deep → applies on_untrusted. Background refresh re-fetches. Dispatch → per-call headers (`x-liminal-persona`, `x-liminal-issuer` if identity=forward; `Authorization` from ctx.credentials if service-token; `x-correlation-id` always) → upstream → UNTRUSTED results wrapped by `frame_untrusted_result` (nonce-tagged banner, hidden unicode stripped from every string at any depth) and flagged `liminal_untrusted*` → routes.py copies to `_meta`.
INVARIANTS:
- `tool_name.split(".",1)[0] == target.name == registry key` is the authz key for allowlist, scope map and credentials. Guarded by tests/test_dispatch_contract.py. Target names: non-empty, no `.`, no collision with handlers or each other (TargetConfigError).
- Only `transport="http"` is served; stdio specs validate but build_http_targets rejects them ("Stage A"). stdio + identity forwarding is rejected at config time (children cannot carry per-request identity).
- Per-call headers are built fresh and NEVER stored on the shared client (#13), so persona A's token cannot ride persona B's request.
- Missing or whitespace-only service-token credential → refusal ToolResult, never an unauthenticated upstream call (#80).
- One target's startup failure does not stop the others (#86); it stays registered and /healthz reports `degraded` with "startup failed" / "catalog fetch failed". A failed catalog = zero tools, visible on /healthz (#75).
- Consumers must trust `_meta["liminal/untrusted"]` + nonce, not the banner text (an upstream can imitate text).
- Unsanitizable upstream content → refusal ToolResult naming target and cause, not an exception.
- Owned httpx client rejects all cookies (#76).
- Target scopes are operator config only (see policy.md); declaring tool_scopes makes the target deny-by-default.
CONSUMERS: server/app.py:create_app (builds all targets), server/routes.py (dispatch, /healthz, `_meta`). Tests: test_http_target.py, test_untrusted_result_framing.py, test_catalog_depth_bound.py, test_cli_targets.py, test_tool_extras_forwarding.py.
API: `liminal.target` exports TargetSpec, build_http_targets, InProcessTarget, Target; `liminal.dispatch` exports Multiplexer, InProcessDispatcher, DispatchError, UnknownTool.
