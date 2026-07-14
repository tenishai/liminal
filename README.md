# limenal

MCP gateway — one MCP connection per agent, many backend handlers behind it.

From Latin *limen*, "threshold." limenal is the boundary an agent crosses to
reach its tools: memory, web fetch, file I/O, notifications, and persona-specific
backends. Instead of every agent running N MCP server processes, agents connect
to one limenal and limenal dispatches.

## Status

**198 tests passing.** All handlers shipped, credential flow complete, MCP spec
compliant, async-clean, SSRF-hardened, CI active on push/PR.

## What works

- **5 built-in handlers** — `scratchpad` (per-agent ephemeral notes), `files`
  (scoped read/write/list/exists with path-traversal defense), `web` (allowlisted
  HTTP fetch + SSRF DNS-rebinding defense via pinned-IP transport), `memory`
  (techne-backed knowledge recall + commit), `notify` (transport-agnostic
  notifications; webhook in v1).
- **JWT auth** — RS256 algorithm pin, `aud` + `cabal_scope` enforcement on every
  call. Wrong audience → 401. No scope → 401.
- **`cabal_tool_extras` clamping** — operator config is the ceiling. JWTs can
  narrow allowed paths/hosts/webhooks but cannot widen past the server-side bound.
- **Credential flow** — `CabalCoreCredentialResolver` fetches per-`(persona, handler)`
  secrets from Cabal Core with TTL caching. Handlers receive credentials in
  `ctx.credentials` with no credential material in source or config files.
- **MCP spec compliance** — all `ToolResult` content blocks are `text` or `image`;
  the non-spec `json` type is converted at the wire boundary. Notifications get no
  response.
- **Async throughout** — JWKS fetch, DNS resolution, file I/O, and SQLite all off
  the event loop via `anyio.to_thread`.
- **MCP client lib** — `MCPClient` (sync) and `AsyncMCPClient` (async) in
  `limenal.client` for downstream consumers (Cabal, third-party agents).

## Why

- **One MCP connection per agent**, not N.
- **Persona-scoped credentials** — limenal fetches the credential set for
  `(persona, handler)` at dispatch time. No `.env` files on disk.
- **Handler pooling** — `rook-primus` and `rook-secundus` share the same `slack`
  handler runtime and rate-limit budget.
- **Same handler interface everywhere** — in-process Python callables today, with a
  federation path (`limenal serve --targets`) for fanning out to upstream MCP servers;
  identical `dispatch(name, payload, ctx)`.
- **Capability cards** declare what each handler covers, what credentials it
  expects, and when it's relevant.

## Quickstart (development)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pip install -e ../techne        # sibling install for the memory handler

pytest -q
```

## Install (non-dev / clean machine)

The `memory` handler needs `techne`, which is not on a public index. To install
without a sibling checkout (agents, other hosts, containers), pin the git source
alongside the extra:

```bash
pip install -r requirements-sources.txt ".[memory]"
```

Dev/CI keep the editable sibling checkout above (`pip install -e ../techne`).

## Run the gateway (`limenal serve`)

Expose the handlers as one MCP endpoint any MCP client (Claude Code, goose, Cabal
personas) connects to. Handlers are **auto-discovered** from installed packages — install
`cabal` alongside limenal and its `patterns` / `documents` / `code` / `archivist`
handlers register automatically next to limenal's own five.

```bash
# local / trusted-network — single operator on localhost, auth off:
LIMENAL_AUTH_DISABLED=1 limenal serve --host 127.0.0.1 --port 9100

# production — verify caller JWTs against Cabal Core's JWKS (swap in your host):
limenal serve --port 9100 --jwks-url https://cabal-core.internal:7400/.well-known/jwks.json
```

`limenal list-handlers` prints what's registered. The endpoint speaks JSON-RPC at
`POST /mcp` (`initialize` / `tools/list` / `tools/call`). Point a client at it — e.g.
Claude Code:

```bash
claude mcp add --transport http limenal http://127.0.0.1:9100/mcp
```

To have credentialed handlers fetch their secrets from Cabal at dispatch time, add
`--cabal-url http://cabal-core:7400 --cabal-token-env LIMENAL_CABAL_TOKEN`. Federate
extra MCP upstreams with `--targets targets.toml`.

## Repository layout

```
src/limenal/
  protocol/        Handler Protocol, Context, ToolSpec, ToolResult, CapabilityCard
  registry/        Entry-point discovery + handler registration
  dispatch/        In-process dispatcher
  server/          MCP HTTP server (POST /mcp), JWT verifiers, credential resolver
  handlers/        scratchpad, files, web, memory, notify
  client/          MCPClient (sync) + AsyncMCPClient (async)
tests/             pytest suite (198 tests)
docs/
  design.md        The proposal this implementation follows
```

## Wiring a handler (custom)

```python
from limenal.protocol import Context, Handler, ToolResult, ToolSpec

class GreetHandler(Handler):
    def tools(self) -> list[ToolSpec]: ...
    def capability_card(self) -> dict: ...
    async def dispatch(self, name: str, payload: dict, ctx: Context) -> ToolResult:
        return ToolResult.text(f"Hello, {payload['name']}!")

def get_handler() -> Handler:
    return GreetHandler()
```

Register via `pyproject.toml`:

```toml
[project.entry-points."limenal.handlers"]
greet = "mypackage.greet:get_handler"
```

## Using the MCP client

```python
from limenal.client import AsyncMCPClient

async with AsyncMCPClient(
    base_url="http://127.0.0.1:9100",   # wherever `limenal serve` is listening
    token_provider=lambda: my_token(),
) as client:
    tools = await client.list_tools()
    result = await client.call_tool("scratchpad.set", {"key": "color", "value": "blue"})
```

## Relationship to Cabal

limenal is standalone — any MCP-speaking agent can use it. Cabal
(`github.com/tenishai/cabal`) is the primary downstream consumer; Cabal personas
connect to limenal for their tool surface and limenal asks Cabal Core for
credentials per `(persona, handler)`.

Sibling-checkout convention: clone `tenishai/limenal` as a sibling of `cabal`
and `techne`, install with `pip install -e ../limenal`.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
