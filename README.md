# limenal

MCP gateway — one MCP connection per agent, many backend handlers behind it.

From Latin *limen*, "threshold." limenal is the boundary an agent crosses to
reach its tools: memory, Slack, GitHub, web fetch, file I/O, persona-specific
backends. Instead of every agent running N MCP server processes, agents connect
to one limenal and limenal dispatches.

## Status

Pre-alpha. Phase 1 (Handler protocol + entry-point discovery + capability cards +
in-process dispatch) in progress. See [`docs/design.md`](docs/design.md) for the
spec the code is following.

## Why

- **One MCP connection per agent**, not N.
- **Persona-scoped credentials** — limenal fetches the credential set for
  `(persona, handler)` at handler-init time. No `.env` files on disk.
- **Handler pooling across same-persona agents** — `rook-primus` and
  `rook-secundus` share the same `slack` handler runtime + rate-limit budget.
- **Same handler interface in solo and scale modes** — Python callables in
  solo, subprocess JSON-RPC in scale, identical `dispatch(name, payload, ctx)`.
- **Capability cards** declare what each handler covers, what credentials it
  expects, and when it's relevant. v1 ships all handlers as `activation: always`;
  v2 lights up on-demand activation for context-window optimization.

## Quickstart (development)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Sibling-installed techne so the `memory` handler tests run.
# (Skip if you don't need the memory backend; the handler is gracefully
# unusable without it.)
pip install -e ../techne

pytest -q
```

## Repository layout

```
src/limenal/
  protocol/        Handler Protocol, Context, ToolSpec, ToolResult, CapabilityCard
  registry/        Entry-point discovery + handler registration
  dispatch/        In-process dispatch path (Phase 1); subprocess JSON-RPC (Phase 2)
  server/          MCP HTTP/SSE server (Phase 1.5)
  handlers/        Built-in reference handlers (scratchpad, files)
tests/             pytest suite
docs/
  design.md        The proposal this implementation follows
```

## Relationship to Cabal

limenal is standalone — anyone with an MCP-speaking agent can use it. Cabal
(github.com/dimartin/cabal) is the primary downstream consumer; Cabal's
personas connect to limenal for their tool surface and limenal asks Cabal Core
for the credential set per `(persona, handler)`.

Sibling-checkout convention (matches Cabal's D-008): clone `dimartin/limenal`
as a sibling of `cabal` and `techne`, install with `pip install -e ../limenal`.

## License

MIT. See [LICENSE](LICENSE).
