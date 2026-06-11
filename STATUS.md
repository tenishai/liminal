# limenal Status — 2026-06-11

First commits laying the foundation. Working from `docs/design.md` (the
proposal carried over from the Cabal workspace).

## Headline

- **GitHub**: https://github.com/dimartin/limenal — private, first commit landing.
- **Tests**: 32 passing, ~0.5s.
- **CLI works**: `limenal version` + `limenal list-handlers --cards` round-trip.

## What landed in this commit (Phase Z)

| Layer | File(s) | What it ships |
|---|---|---|
| protocol | `src/limenal/protocol/{handler,context,tool,card}.py` | Handler Protocol, Context dataclass, ToolSpec / ToolResult pydantic models, CapabilityCard schema + validator |
| registry | `src/limenal/registry/discover.py` | Entry-point group discovery (`limenal.handlers`), per-handler fail-open error handling, name-keyed Registry, explicit-register escape hatch for tests |
| dispatch | `src/limenal/dispatch/local.py` | InProcessDispatcher; list_tools prefixes with handler name; handler exceptions become ToolResult.failure not propagating raises |
| handlers | `src/limenal/handlers/scratchpad.py` | Reference handler — per-(identity, agent) ephemeral notes, no credentials, full set / get / list / clear |
| cli | `src/limenal/cli.py` | `limenal version` + `limenal list-handlers [--cards]` |
| docs | `docs/design.md` | The original proposal, vendored from cabal workspace |

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

- **MCP HTTP/SSE server** (`server/`): the agent-facing wire transport.
  Phase 1.5 — call it the moment a real MCP client needs to connect.
- **Credential resolution** from a Cabal Core URL: today Context.credentials
  is whatever the caller passes; Phase 1.6 adds the `(persona, handler)` →
  credentials fetch + 15-minute TTL cache (design.md §"Credential Flow").
- **Subprocess JSON-RPC mode** (scale mode): the same Handler contract, but
  with the handler running in a separate process. Adds crash-loop circuit
  breaker (5 in 60s → QUARANTINED). Phase 2.
- **`toolset.yaml`** loader: per-persona handler allowlists. Small.
- **More built-in handlers**: `files` (scoped read/write), `web` (allowlisted
  fetch), `memory` (techne proxy), `patterns` (Architect pattern corpus
  surface). Each is its own small project.
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
