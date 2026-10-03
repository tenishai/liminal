---
card: arch-card:liminal-handler-protocol
updated: 2026-10-03
anchor: src/liminal/protocol/handler.py sha=adfe378e757a7889f1a9a6f48983859fccb44296
anchor: src/liminal/registry/discover.py sha=6a348939f6216d5d2bb6b94e9872a69b8ca4b7af
anchor: src/liminal/protocol/card.py sha=f1fe47125cc56c1e138076bdda7140b33b5f6198
anchor: src/liminal/protocol/context.py sha=5b7f5acd34f387424f37b19dbf51eff3f0c82bad
---
# handler-protocol — the in-process extension surface

WHAT / SEAM: `Handler` (typing.Protocol, runtime_checkable; protocol/handler.py): `tools() -> list[ToolSpec]` (sync), `capability_card() -> dict`, `async dispatch(name, payload, ctx: Context) -> ToolResult`. Optional `startup()`/`shutdown()` coroutines are called if present (target/inprocess.py). Structural: no base class needed.
TYPES: ToolSpec(name, description, input_schema) and ToolResult(content, is_error, error; `.text/.json/.failure`) in protocol/tool.py, both pydantic `extra="allow"`. CapabilityCard (protocol/card.py): handler, description, tools[{name, description, required_scope, requires_operator}], activation (always|on_demand; only `always` is used), relevance_signals, credential_keys (documentation only, not enforced), labels, required_scope.
Context (protocol/context.py): identity (persona), agent_name, credentials, issuer, extra (sandbox config), granted_scopes (server grant only), audit (hook; sovereign only).
OPS / FLOW: registry/discover.py:discover_handlers scans entry-point group `liminal.handlers` → `ep.load()` → factory() → isinstance(Handler) → validate_card → Registry keyed by ENTRY-POINT NAME (not card.handler). create_app wraps each record as an InProcessTarget in the Multiplexer. Tool is exposed as `<ep-name>.<tool>`.
INVARIANTS:
- Discovery is FAIL-OPEN per handler: import error, factory raise, protocol mismatch, bad card → logged + skipped. WHY: one broken plugin must not black-hole every agent's tool surface. Consequence: a missing handler shows only in logs / `liminal list-handlers`.
- Duplicate entry-point name → last one wins, with a warning (Registry.register).
- Handler exceptions never propagate: Multiplexer.dispatch converts them to `ToolResult.failure("<t>.<tool> raised <Type>")`. Return ToolResult.failure for errors the agent can act on.
- Card `required_scope` (handler-level) and per-tool `required_scope` feed the sovereign scope map (app.py:scope_for). Per-tool WINS even when weaker than handler-level (no max) — use it to narrow, never widen. A per-tool `requires_operator: true` (default false) marks an operator-only tool: app.py:operator_only_tools collects them and routes.py:_operator_refusal enforces it at tools/call and filters it from tools/list in EVERY auth mode, independently of `required_scope` (single-cabal: token `cabal_scope`/`scope` must hold `operator`; sovereign: the grant must hold `operator` or `admin:*`; auth-disabled: refused). Federated targets have no such flag.
- Handlers must read sandbox bounds from `ctx.extra` and authz from `ctx.granted_scopes`, never from `ctx`-independent token data; routes.py fills both according to auth mode.
- Never add a module-scope hard `import techne` (memory is optional); new capability goes in handlers/ + a pyproject entry point, not branches in gateway code.
CONSUMERS: in-tree handlers/{scratchpad,web,files,memory,notify}.py (pyproject entry points); cabal/src/cabal/handlers/{patterns,documents,code,archivist}.py (cabal pyproject `[project.entry-points."liminal.handlers"]`); client/library.py (LibraryLiminalClient calls InProcessDispatcher directly). Contract tripwire: tests/test_dispatch_contract.py, tests/test_registry.py.
API: `liminal.protocol` exports Handler, Context, ToolSpec, ToolResult, CapabilityCard, ActivationMode, CardValidationError, validate_card; `liminal.registry` exports DiscoveryError, HandlerRecord, Registry, discover_handlers. `register_explicit(registry, name, handler, *, source="explicit")` (tests/embedding) is defined in registry/discover.py but NOT exported from registry/__init__.py; import it as `from liminal.registry.discover import register_explicit`. How-to: docs/writing-a-handler.md.
