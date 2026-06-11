# limenal Status — 2026-06-11

First commits laying the foundation. Working from `docs/design.md` (the
proposal carried over from the Cabal workspace).

## Headline

- **GitHub**: https://github.com/dimartin/limenal — private, MCP server landing.
- **Tests**: 58 passing, ~0.6s.
- **CLI works**: `limenal version`, `limenal list-handlers --cards`, `limenal serve` round-trip.
- **MCP server works end-to-end**: handshake, JWT auth, tools/list, tools/call, per-(persona, agent) isolation.

## What landed in this commit (Phase Z)

| Layer | File(s) | What it ships |
|---|---|---|
| protocol | `src/limenal/protocol/{handler,context,tool,card}.py` | Handler Protocol, Context dataclass, ToolSpec / ToolResult pydantic models, CapabilityCard schema + validator |
| registry | `src/limenal/registry/discover.py` | Entry-point group discovery (`limenal.handlers`), per-handler fail-open error handling, name-keyed Registry, explicit-register escape hatch for tests |
| dispatch | `src/limenal/dispatch/local.py` | InProcessDispatcher; list_tools prefixes with handler name; handler exceptions become ToolResult.failure not propagating raises |
| handlers | `src/limenal/handlers/scratchpad.py` | Reference handler — per-(identity, agent) ephemeral notes, no credentials, full set / get / list / clear |
| cli | `src/limenal/cli.py` | `limenal version` + `limenal list-handlers [--cards]` + `limenal serve` |
| docs | `docs/design.md` | The original proposal, vendored from cabal workspace |

## What landed in Phase AA — MCP HTTP server

| Layer | File(s) | What it ships |
|---|---|---|
| server/mcp_types | `mcp_types.py` | JSON-RPC envelope + InitializeParams/Result, ToolsListResult, ToolCallParams/Result, ServerInfo, error codes (-32700..-32603 standard + -32001..-32003 server-defined) |
| server/auth | `auth.py` | JWTVerifier Protocol; StaticKeySetVerifier (tests) and URLJWKSVerifier (prod) with TTL cache + kid-miss refresh. Returns VerifiedClaims{identity, agent_name, raw} extracted from cabal_persona + sub claims |
| server/routes | `routes.py` | POST /mcp dispatching initialize / notifications/initialized / ping / tools/list / tools/call; auth gate skips public methods; tool_call resolves credentials via injectable callable and builds Context for the dispatcher. GET /healthz |
| server/app | `app.py` | create_app(jwt_verifier, registry, credential_resolver, server_name) — registry defaults to discover_handlers(), credential_resolver defaults to None (empty credentials) |

## What works end-to-end now

- A package declares `[project.entry-points."limenal.handlers"]` with a
  `name = "module:get_handler"` line.
- `pip install`-ing the package registers it.
- `limenal list-handlers` shows it.
- `InProcessDispatcher.dispatch(tool_name="<handler>.<tool>", payload, ctx)`
  invokes it with the right Context (identity, agent, credentials).
- Failures inside the handler don't propagate; they come back as
  ToolResult.failure with a readable message.
- Per-(identity, agent_name) isolation in scratchpad is enforced + tested.

## What's NOT built yet — next session targets

- **Streaming responses** (text/event-stream variant per the MCP "Streamable HTTP"
  transport): right now every response is a single JSON body. SSE for tool
  calls that want to stream tokens lands in Phase 1.6.
- **Real Cabal Core credential fetch**: the `credential_resolver` callable
  is wired into the server; production needs an httpx-based implementation
  that calls `GET https://cabal-core/secrets/{persona}/{handler}` with mTLS
  + the 15-minute TTL cache from design.md §"Credential Flow".
- **Subprocess JSON-RPC mode** (scale mode): the same Handler contract, but
  with the handler running in a separate process. Adds crash-loop circuit
  breaker (5 in 60s → QUARANTINED). Phase 2.
- **`toolset.yaml`** loader: per-persona handler allowlists.
- **More built-in handlers**: `files` (scoped read/write), `web` (allowlisted
  fetch), `memory` (techne proxy), `patterns` (Architect pattern corpus
  surface).
- **Integration with Cabal**: the `tool_use` hook in Cabal Core fires
  against limenal once both sides are wired.

## Sibling-checkout convention

Matches Cabal D-008. Operators clone all three repos as siblings:

```
parent/
├── cabal/
├── limenal/
└── techne/
```

Cabal integration (when it lands) will use `pip install -e ../limenal` the
same way it currently does `pip install -e ../techne`. PyPI publish gates
public release of all three (see Cabal's STATUS.md checklist).
