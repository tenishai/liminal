# liminal

MCP gateway — one MCP connection per agent, many backend handlers behind it.

From Latin *limen*, "threshold." liminal is the boundary an agent crosses to
reach its tools: memory, web fetch, file I/O, notifications, and persona-specific
backends. Instead of every agent running N MCP server processes, agents connect
to one liminal and liminal dispatches.

## Status

All handlers shipped, credential flow complete, MCP spec compliant, async-clean,
SSRF-hardened, CI active on push/PR. Run `pytest -q` for the current suite.

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
  `liminal.client` for downstream consumers (Cabal, third-party agents).

## Why

- **One MCP connection per agent**, not N.
- **Persona-scoped credentials** — liminal fetches the credential set for
  `(persona, handler)` at dispatch time. No `.env` files on disk.
- **Handler pooling** — `rook-primus` and `rook-secundus` share the same `slack`
  handler runtime and rate-limit budget.
- **Same handler interface everywhere** — in-process Python callables today, with a
  federation path (`liminal serve --targets`) for fanning out to upstream MCP servers;
  identical `dispatch(name, payload, ctx)`.
- **Capability cards** declare what each handler covers, what credentials it
  expects, and when it's relevant.

## Quickstart (development)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pip install -e ../techne        # OPTIONAL: only the memory handler needs techne,
                                # and techne is not public yet. Everything else,
                                # including the test suite, runs without it.

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

The PyPI distribution is named `tenishai-liminal`; the import package and the CLI
command are still `liminal`. To install a tagged release straight from git:

```bash
pip install "tenishai-liminal @ git+https://github.com/tenishai/liminal.git@<tag>"
```

## Run the gateway (`liminal serve`)

Expose the handlers as one MCP endpoint any MCP client (Claude Code, goose, Cabal
personas) connects to. Handlers are **auto-discovered** from installed packages — install
`cabal` alongside liminal and its `patterns` / `documents` / `code` / `archivist`
handlers register automatically next to liminal's own five.

```bash
# local / trusted-network — single operator on localhost, auth off:
LIMINAL_AUTH_DISABLED=1 liminal serve --host 127.0.0.1 --port 9100
#
# The `files` handler starts with an EMPTY allowlist and refuses every call
# until you grant it something. In auth-off mode there is no JWT to carry a
# per-persona allowlist, so grant the operator ceiling by environment:
#
#   LIMINAL_FILES_ALLOWED_PATHS=/srv/work:/tmp/sandbox \
#     LIMINAL_AUTH_DISABLED=1 liminal serve --host 127.0.0.1 --port 9100
#
# os.pathsep-separated, read once at startup. Relative segments are refused.
#
# WHAT IT MEANS DEPENDS ON THE CALLER:
#   no files.allowed_paths claim  -> this IS the grant (auth-off is this case)
#   a claim  -> this is the CEILING; the claim narrows it, never widens it
#   an empty or malformed claim   -> nothing is granted
#
# So on a JWT deployment, setting this grants it to every token WITHOUT the
# claim — it is not only a ceiling. `web`, `scratchpad` and `notify` need no
# such grant.

# production — verify caller JWTs against Cabal Core's JWKS (swap in your host):
liminal serve --port 9100 --jwks-url https://cabal-core.internal:7400/.well-known/jwks.json
```

`liminal list-handlers` prints what's registered. The endpoint speaks JSON-RPC at
`POST /mcp` (`initialize` / `tools/list` / `tools/call`). Point a client at it — e.g.
Claude Code:

```bash
claude mcp add --transport http liminal http://127.0.0.1:9100/mcp
```

To have credentialed handlers fetch their secrets from Cabal at dispatch time, add
`--cabal-url http://cabal-core:7400 --cabal-token-env LIMINAL_CABAL_TOKEN`. Federate
extra MCP upstreams with `--targets targets.toml`.

## Repository layout

```
src/liminal/
  protocol/        Handler Protocol, Context, ToolSpec, ToolResult, CapabilityCard
  registry/        Entry-point discovery + handler registration
  dispatch/        In-process dispatcher
  server/          MCP HTTP server (POST /mcp), JWT verifiers, credential resolver,
                   policy store, admin surface, secret guard
  target/          Federated targets — the machinery behind `--targets`
  handlers/        scratchpad, files, web, memory, notify
  client/          MCPClient (sync) + AsyncMCPClient (async)
tests/             pytest suite
docs/
  design.md        The ORIGINAL proposal. The implementation has diverged —
                   read this README for what shipped.
  proposals/       Design notes, not documentation of current behaviour
```

## Wiring a handler (custom)

```python
from liminal.protocol import Context, Handler, ToolResult, ToolSpec

# No base class: `Handler` is a typing.Protocol, so conforming is structural.
# None of the shipped handlers subclass it; the import is for the return type.
class GreetHandler:
    def tools(self) -> list[ToolSpec]: ...
    def capability_card(self) -> dict: ...
    async def dispatch(self, name: str, payload: dict, ctx: Context) -> ToolResult:
        return ToolResult.text(f"Hello, {payload['name']}!")

def get_handler() -> Handler:
    return GreetHandler()
```

Register via `pyproject.toml`:

```toml
[project.entry-points."liminal.handlers"]
greet = "mypackage.greet:get_handler"
```

That's the mechanism. Before you write a real handler, read
[`docs/writing-a-handler.md`](docs/writing-a-handler.md) — four things
(`ctx.extra`'s security contract, silent discovery failure, a scope-gating
footgun, the testing convention) that this sketch doesn't cover and that
you'd otherwise have to find in source.

## Using the MCP client

```python
from liminal.client import AsyncMCPClient

async with AsyncMCPClient(
    base_url="http://127.0.0.1:9100",   # wherever `liminal serve` is listening
    token_provider=lambda: my_token(),
) as client:
    tools = await client.list_tools()
    result = await client.call_tool("scratchpad.set", {"key": "color", "value": "blue"})
```

## Relationship to Cabal

liminal is standalone — any MCP-speaking agent can use it. Cabal
(`github.com/tenishai/cabal`) is the primary downstream consumer; Cabal personas
connect to liminal for their tool surface and liminal asks Cabal Core for
credentials per `(persona, handler)`.

Sibling-checkout convention: clone `tenishai/liminal` as a sibling of `cabal`
and `techne`, install with `pip install -e ../liminal`.

## License

Copyright (C) 2026 tenishai

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.

Full text: [LICENSE](LICENSE).
