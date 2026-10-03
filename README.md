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
- **JWT auth** — RS256 algorithm pin and `aud` enforcement on every authenticated
  method (`tools/list`, `tools/call`); `initialize` and `ping` need no token. In
  single-cabal mode (`--jwks-url`) the token must also hold the `dispatch` scope,
  in a `cabal_scope` claim, or failing that a `scope` claim, given as a JSON array
  (a space-delimited string is rejected; a non-list `cabal_scope` hides a valid `scope`). In sovereign mode (`--trust-registry` + `--policy-db`) the
  token's own scope and tool extras are ignored, and access comes from the
  server-side grant for its `(issuer, persona)`. An auth failure on `/mcp` (wrong
  audience, no scope, no grant) is HTTP 200 carrying JSON-RPC error `-32001`; only
  `/admin/*` answers with a real 401.
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
- **Handler pooling** — personas share one runtime per handler, so `rook-primus`
  and `rook-secundus` reach the same `web` handler instance. A credentialed
  handler, such as a hypothetical `slack` one (none ships), could keep one
  rate-limit budget for both.
- **Same handler interface everywhere** — in-process Python callables today, with a
  federation path (`liminal serve --targets`) for fanning out to upstream MCP servers;
  identical `dispatch(name, payload, ctx)`.
- **Capability cards** declare what each handler covers, what credentials it
  expects, and when it's relevant.

## Quickstart (development)

You need git and Python 3.12 or newer. On Debian and Ubuntu, also run
`sudo apt update && sudo apt install python3-venv`; without it `python3 -m venv`
fails. liminal and techne are both private for now, so until they are public the
clone needs access to `tenishai/liminal`, and the techne steps below need access
to `tenishai/techne`.

```bash
git clone https://github.com/tenishai/liminal.git && cd liminal
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Everything above, including the test suite, runs without techne. Only the
`memory` handler needs it. Until techne is public, this step needs access to
`tenishai/techne`:

```bash
pip install -r requirements-sources.txt   # techne at its pinned git tag, no sibling checkout
pip install -e ".[dev,memory]"
```

## Install (non-dev / clean machine)

The `memory` handler needs `techne`, which is not on a public index. To install
without a sibling checkout (agents, other hosts, containers), work from a clone of
this repo (see the Quickstart above, including its Debian/Ubuntu `python3-venv`
step), with access to `tenishai/techne`, and pin the git source alongside the extra
inside a virtual environment:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-sources.txt ".[memory]"
```

If you work on techne and liminal together, install your techne checkout instead:
`pip install -e ../techne`.

The pinned techne is `v0.18.0`, stated in `requirements-sources.txt`, in the `memory`
extra's floor, and as the Dockerfile's `TECHNE_VERSION`; `tests/test_techne_pin.py`
keeps the three in step. To build the image from a sibling checkout, clone techne at
that tag and check it before building:

```bash
git clone --branch v0.18.0 https://github.com/tenishai/techne.git ../techne
bash scripts/check-techne-sibling.sh
docker build --build-context techne=../techne -t liminal .
```

The image build itself only compares techne's version string, which cannot tell
techne's main from the tag; the script compares commits. `TECHNE_ANY=1` skips the
script and `--build-arg TECHNE_ANY_VERSION=1` skips the build's check, for building
against whatever `../techne` has checked out.

The distribution is named `tenishai-liminal` (not yet published to PyPI); the
import package and the CLI command are still `liminal`. To install a tagged release
straight from git (this needs access to `tenishai/liminal` until it is public):

```bash
pip install "tenishai-liminal @ git+https://github.com/tenishai/liminal.git@<tag>"
```

`v0.3.0` is the first tag that builds `tenishai-liminal`; `v0.2.0` builds the old `liminal`
distribution and `v0.1.0` builds `limenal`.

## Run the gateway (`liminal serve`)

Expose the handlers as one MCP endpoint any MCP client (Claude Code, goose, Cabal
personas) connects to. Handlers are **auto-discovered** from installed packages — install
`cabal` alongside liminal and its `patterns` / `documents` / `code` / `archivist`
handlers register automatically next to liminal's own five.

```bash
# local / trusted-network — single operator on localhost, auth off:
LIMINAL_AUTH_DISABLED=1 liminal serve --host 127.0.0.1 --port 9100
# health check: curl http://127.0.0.1:9100/healthz
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

# production — verify caller JWTs against Cabal Core's JWKS (swap in your host).
# --host defaults to 127.0.0.1; 0.0.0.0 listens on every interface:
liminal serve --host 0.0.0.0 --port 9100 --jwks-url https://cabal-core.internal:7400/.well-known/jwks.json
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
  client/          LiminalClient protocol, LibraryLiminalClient (in-process),
                   ProxyLiminalClient (HTTP, wraps AsyncMCPClient), from_config,
                   MCPClient (sync) + AsyncMCPClient (async)
  wire.py          Wire-format helpers shared by the server and the library client
scripts/           check-techne-sibling.sh (sibling techne matches the pinned tag)
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
