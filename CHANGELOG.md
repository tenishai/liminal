# Changelog

All notable changes to liminal are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses semantic versioning.
Each line cites the pull request that made the change.

## [Unreleased]

### Added

- **`http` targets accept a static `headers` table in `targets.toml`** (tenishai/liminal#135, closes tenishai/liminal#130),
  for example `X-MCP-Readonly = "true"` for GitHub's hosted MCP server. The headers go on
  `initialize`, `tools/list` and `tools/call`. Config load refuses `Authorization`,
  `Mcp-Session-Id`, `Accept`, `Content-Type` and liminal's identity headers
  (`X-Liminal-Persona`, `X-Liminal-Issuer`, `X-Correlation-Id`) in any case, and refuses
  `headers` on a `stdio` target.
- **The MCP client reads Streamable-HTTP SSE responses** (tenishai/liminal#129). Both
  clients send `Accept: application/json, text/event-stream` on every POST and, when a
  server answers with `text/event-stream`, return the JSON-RPC message whose `id` matches
  the request, stopping there rather than waiting for the stream to close. Plain JSON
  servers are unaffected. This lets GitHub's hosted MCP server
  (`https://api.githubcopilot.com/mcp`) be federated as an `http` target; it always
  streams and rejects a JSON-only Accept with 400.
- **`use_session=True` on either client keeps the server's `Mcp-Session-Id`** from
  `initialize` and sends it on later requests (tenishai/liminal#129). It is off by
  default and `HttpTarget` does not enable it, because its shared client must stay
  stateless across personas (tenishai/liminal#76).
- **`LIMINAL_FILES_ALLOWED_PATHS` grants the `files` handler its allowlist without a JWT**
  (tenishai/liminal#100). Auth-off mode has no token to carry a per-persona allowlist, so
  every `files` call was refused. The variable is `os.pathsep`-separated and read once at
  startup; unset still refuses everything, and a JWT claim can narrow it but not widen it.
- **`liminal serve --admin-port` / `--admin-host` serve the admin surface on its own
  listener**, and `create_app(mount_admin=False)` keeps `/admin/*` off the data-plane app
  (tenishai/liminal#83).
- **`admin_personas` on the trust registry's parent issuer** narrows who holds admin
  standing, and `liminal serve --audience` sets the expected audience for a single-issuer
  verifier (tenishai/liminal#83).
- **Per-tool scopes for federated targets.** A target in `--targets` takes `required_scope`
  and `tool_scopes`, authored by the operator and never read from the upstream's catalog.
  Declaring `tool_scopes` denies any tool not named (tenishai/liminal#81).
- **Untrusted federated results carry a marker.** Results from a target with
  `trust = "untrusted"` are wrapped in a nonce-tagged envelope, hidden and bidi-control
  Unicode is stripped, and the JSON-RPC result carries `_meta` keys `liminal/untrusted`,
  `liminal/untrusted_source` and `liminal/untrusted_nonce` (tenishai/liminal#82).
- **`/healthz` reports per-target status** with a `degraded` rollup when a target's
  catalog fetch failed or its startup failed (tenishai/liminal#84, tenishai/liminal#109).
- **Docs:** `docs/writing-a-handler.md` (tenishai/liminal#101), `SECURITY.md`
  (tenishai/liminal#106), a copyright notice, `AGENTS.md` and a README that marks techne
  as optional (tenishai/liminal#99).

### Changed

- **A tool-level failure now reaches the agent as text.** `ToolResult.failure(msg)` used to
  serialise as `{"content": [], "isError": true}`; the message is now a text content block
  (tenishai/liminal#70).
- **Parent policy rows no longer answer on the data plane.** Admin standing moves to a
  dedicated lookup used only by the admin gate. Parent rows seed per persona, defaulting to
  `*` as before. A registry whose only issuer is the parent, with no `admin_personas`, is
  refused at startup with exit 2 (tenishai/liminal#83).
- **`initialize` is authenticated** like every other call to an upstream. An empty token
  still sends no header (tenishai/liminal#84).
- **Transport errors carry the cause once.** The client message is now
  `<httpx class>: <cause>`, so agents no longer see "transport error:" twice. `str(exc)` on
  `MCPTransportError` no longer starts with `transport error:` (tenishai/liminal#112).
- **The distribution is named `tenishai-liminal`** (was `liminal`). The bare names are
  taken or open to squatting on PyPI. The import package (`liminal`) and the CLI command
  (`liminal`) are unchanged. `liminal.__version__` now reads the new distribution's
  metadata, and a pin such as `liminal>=0.2` becomes `tenishai-liminal>=0.2`
  (tenishai/liminal#118). An existing editable install keeps the old `liminal`
  distribution beside the new one; run `pip uninstall liminal` and reinstall.
- **The techne floor and source pin move to 0.17.0** (tenishai/liminal#96).
- **The Docker image builds from a sibling techne checkout or a package index.** Pass
  `--build-context techne=../techne` or `--build-arg EXTRA_INDEX_URL=...`; with neither,
  the build stops and says which (tenishai/liminal#117).
- **`relevance_signals` is removed from `CapabilityCard`, the built-in handler cards and
  `TargetSpec`** (tenishai/liminal#136, closes tenishai/liminal#116). Nothing read it; it was plumbed for a routing layer
  that does not exist. A `[[target]]` table that still sets it now fails with an unknown-key
  error. Cards from other handler packages that still declare it keep validating, since
  `CapabilityCard` allows extra fields, and the value is ignored.

### Fixed

- **The credential resolver no longer caches an empty answer** (tenishai/liminal#140,
  closes tenishai/liminal#139). A 200 whose `credentials` is empty, null or missing is
  returned uncached, so a secret added later is seen on the next call; a body that is not
  a JSON object now returns `{}` as a wrong-shape answer instead of raising
  `AttributeError`.
- **The MCP client reuses its connection after an SSE reply** (tenishai/liminal#138, closes tenishai/liminal#132). Both
  clients stopped reading at the reply, before the chunked terminator, so an
  SSE-answered call almost never reused a connection: 13 requests on one client opened 12
  connections against a local SSE server. They now drain the rest of the
  stream for up to `sse_drain_timeout` seconds (default 0.5) and close the connection if
  the server holds the stream open longer. Plain JSON replies are unchanged.
- **A JSON reply that is not an object is a clean `MCPTransportError`** in both clients,
  instead of an `AttributeError` on `.get` (tenishai/liminal#129).
- **The README quickstart runs as written on a fresh Ubuntu machine** (tenishai/liminal#128).
  `sudo apt update` precedes the `python3-venv` install, the non-dev install creates a
  virtual environment first, and the health endpoint (`/healthz`) is named. Found by the
  2026-10-02 clean-machine run (tenishai/agora#47).
- **The Docker image no longer ships an empty `liminal/__init__.py`** (tenishai/liminal#127).
  The dependency-cache stub left setuptools' `build/` tree behind, so the real install
  reused it and the container crash-looped on `ImportError: cannot import name
  '__version__'`. The Dockerfile now removes `build/` with the stub, and the build
  fails if the installed package can't import its version. A new `.dockerignore` keeps a
  host-side `build/` or `*.egg-info` out of every build that copies this checkout.
- **`tools/list` no longer shows tools the caller cannot call.** Discovery and `tools/call`
  now share one scope check in sovereign mode (tenishai/liminal#112).
- **The scope-gate deny audit row carries `detail.handler`**, matching the allowlist deny
  (tenishai/liminal#112).
- **A catalog fetch failure is loud** (error log and a degraded `/healthz`) instead of
  leaving a target quietly serving zero tools (tenishai/liminal#84).
- **Package metadata matches the tag.** `pyproject.toml` said 0.1.0 at tag v0.2.0, so
  installs reported the wrong version. It now says 0.2.0, and
  `tests/test_version_tags.py` fails when a reachable tag is newer than pyproject
  (tenishai/liminal#112).
- **Docs:** target `address` examples no longer end in `/mcp`, `design.md` has correction
  notes and a section on the standalone auth-off trust boundary, and the README handler
  example no longer subclasses `Handler` (tenishai/liminal#112).

### Security

- **Demoting the parent issuer in the trust registry left it a parent.** Its parent rows
  survived, so its personas still passed the admin gate. `liminal serve` now refuses to
  start (exit 2) when the policy DB holds parent rows for an issuer the registry no longer
  names as parent (tenishai/liminal#134, closes tenishai/liminal#87).
- **The sync `MCPClient` now coerces an upstream error `code` like the async client**
  (tenishai/liminal#129). It never received tenishai/liminal#82's guard, so a hostile
  upstream could put arbitrary text in `code`. Both clients now share one response parser,
  for plain JSON and SSE alike.
- **A parent policy row could grant data-plane tool access to any persona** through the
  wildcard fallback. It cannot now (tenishai/liminal#83).
- **Upstream `Set-Cookie` no longer persists**, so a session set on one persona's call
  cannot replay on another's (tenishai/liminal#84).
- **A `service-token` dispatch whose credential did not resolve is refused** before
  anything is dialed, instead of going out unauthenticated (tenishai/liminal#84).
- **One hostile upstream schema could abort startup.** Schema inspection is now bounded in
  depth and node count; a tool past either bound is reported as `unscannable-schema` and
  dropped or flagged per the target's policy, and each target starts in isolation
  (tenishai/liminal#109).
- **`files.write` refuses agent-instruction files** (`CLAUDE.md`, `AGENTS.md`,
  `.cursorrules`, `GEMINI.md`, anything under `.claude/`) unless the server-side grant
  carries `files:protected_writes` (tenishai/liminal#109).
- **`files.write` refuses more protected paths and any hard-linked file** without
  `files:protected_writes` (tenishai/liminal#137, closes tenishai/liminal#110): `.gemini/`, `.vscode/mcp.json`,
  `.github/instructions/`, `.clinerules/`, `.cline/rules/`, `.windsurf/rules/`,
  `.devin/rules/`, `.roo/`, `.roorules` and `.roorules-*`. A regular file with more than one
  link is refused because its other names cannot be checked; this holds when the extra link
  exists at the check, and a link made after the open-time re-check and before the write
  ends is not caught. `LIMINAL_FILES_PROTECTED_PATTERNS`
  adds operator fnmatch patterns to the built-in set; it cannot remove one.
- **The runtime image runs `apt-get upgrade`**, so base-image CVEs fixed upstream reach a
  rebuild on a cached base (tenishai/liminal#92).
- **A test pins that single-cabal mode does not accept `admin:*` as operator.** Only a
  token scope of `operator` passes the operator-only gate; a sovereign grant with `admin:*`
  still does (tenishai/liminal#124).

## [0.2.0] — 2026-08-10

### Added

- **Per-tool scope enforcement**, with the scope map derived from handler capability cards
  (tenishai/liminal#41, tenishai/liminal#43).
- **A fail-closed secret guard** that refuses to persist secret-shaped values
  (tenishai/liminal#51), with a fix for false positives on digit-free kebab slugs
  (tenishai/liminal#53).
- **`LIMINAL_MEMORY_DB`** sets the memory handler's database path for `liminal serve`
  (tenishai/liminal#46).
- **A `liminal serve` quickstart** in the README (tenishai/liminal#49).
- **A draft proposal** for the MCP 2026-07-28 dual-era migration (tenishai/liminal#63).

### Changed

- **Project renamed from "limenal" to "liminal"**, the correct spelling
  (tenishai/liminal#65). The `LIMENAL_*` environment variables became `LIMINAL_*`.

### Fixed

- **Strict MCP clients get spec-compliant JSON-RPC** (tenishai/liminal#47).
- **The no-auth client sends no `Authorization` header**, and `create_app` config errors
  exit 2 (tenishai/liminal#45).

## [0.1.0] — 2026-07-10

First tagged release. A handler protocol, registry and dispatcher behind an MCP HTTP
server (`POST /mcp`) with JWT verification (RS256 pin, audience and scope checks, JWKS
with multiple issuers). Built-in handlers: `scratchpad`, `files`, `web` (SSRF defence with
a pinned-IP transport), `memory` (techne-backed) and `notify`. A sync and async MCP
client, a credential resolver backed by Cabal Core, a server-side policy store with
federation admin, federated HTTP targets from a declarative `--targets` file, and a
generic MCP proxy handler. Licensed AGPL-3.0-or-later.
