# What works

What the gateway does today, feature by feature. The README's Status section is the short form.

- **7 built-in handlers** — `scratchpad` (per-agent ephemeral notes), `files`
  (scoped read/write/list/exists with path-traversal defense), `web` (allowlisted
  HTTP fetch + SSRF DNS-rebinding defense via pinned-IP transport), `memory`
  (techne-backed knowledge recall + commit), `notify` (transport-agnostic
  notifications; webhook in v1), `aws` (read-only AWS calls through an IAM role that
  trusts the gateway's own Google identity; needs the `[aws]` extra), `cabal` (sends
  tasks to cabal's personas over A2A; see `docs/cabal-handler.md`).
- **Call audit** — every `tools/call` that reaches a handler logs one `tool.call` line;
  in sovereign mode it also writes an audit row, read with `GET /admin/policy/audit`
  (`persona=`, `agent=`, `since=`, `limit=` up to 1000).
- **JWT auth** — RS256 algorithm pin and `aud` enforcement on every authenticated
  method (`tools/list`, `tools/call`); `initialize` and `ping` need no token. In
  single-cabal mode (`--jwks-url`) the token must also hold the `dispatch` scope,
  in a `cabal_scope` claim, or failing that a `scope` claim, given as a JSON array
  (a space-delimited string is rejected; a non-list `cabal_scope` hides a valid `scope`). In sovereign mode (`--trust-registry` + `--policy-db`) the
  token's own scope and tool extras are ignored, and access comes from the
  server-side grant for its `(issuer, persona)`. An auth failure on `/mcp` (wrong
  audience, no scope, no grant) is HTTP 200 carrying JSON-RPC error `-32001`; only
  `/admin/*` answers with a real 401.
- **Revocation** — with `--cabal-url` set, liminal reads that cabal's
  `GET /auth/revocations` with the `LIMINAL_CABAL_TOKEN` bearer and refuses a token
  from that cabal (in sovereign mode, the parent) whose subject it revoked, within
  the refresh window (`--revocation-ttl`, 30s by default). The check is fail-soft:
  an older cabal that answers 404, or one that is down at start, leaves tokens
  accepted until their `exp` as before (one warning), and a failed refresh keeps
  the last good list.
- **`cabal_tool_extras` clamping** — operator config is the ceiling. JWTs can
  narrow allowed paths/hosts/webhooks but cannot widen past the server-side bound.
- **Credential flow** — `CabalCoreCredentialResolver` fetches per-`(persona, handler)`
  secrets from Cabal Core with TTL caching; a failed fetch gives the handler an empty
  set. Handlers receive per-persona secrets in `ctx.credentials`, and they are not
  stored in this repo. Federated-target tokens (an inline `bearer_token` in a
  `[[target]]`) and the notify webhook URL (a credential itself, in
  `LIMINAL_NOTIFY_WEBHOOK_URL` or tool extras) can also sit in config; prefer
  `bearer_token_env` and Cabal secrets.
- **MCP wire format** — the non-spec `json` block type is converted to `text` at the
  wire boundary; other block types (such as `resource` blocks from federated
  upstreams) pass through as the handler or upstream sent them. Notifications get no
  response.
- **Async** — network calls are awaited; DNS resolution, file reads and writes, and
  SQLite run in a worker thread (`anyio.to_thread` or `asyncio.to_thread`). Path
  resolution in `files` still runs on the event loop.
- **MCP client lib** — `MCPClient` (sync) and `AsyncMCPClient` (async) in
  `liminal.client` for downstream consumers (Cabal, third-party agents).
- **Federated targets** — `liminal serve --targets targets.toml` adds upstream MCP
  servers behind the same endpoint. A target can send static headers, a bearer or HTTP
  Basic credential (inline or from an environment variable), or a per-persona service
  token, and can hold one upstream session per calling persona for a stateful server
  (`session = "per-persona"`). The keys are in the `[[target]]` table in
  `docs/design.md`.

## Why

- **One MCP connection per agent**, not N.
- **Persona-scoped credentials** — liminal fetches the credential set for
  `(persona, handler)` at dispatch time. No `.env` files on disk.
- **Handler pooling** — personas share one runtime per handler, so `mason-primus`
  and `mason-secundus` reach the same `web` handler instance. A credentialed
  handler, such as a hypothetical `slack` one (none ships), could keep one
  rate-limit budget for both.
- **Same handler interface everywhere** — in-process Python callables today, with a
  federation path (`liminal serve --targets`) for fanning out to upstream MCP servers;
  identical `dispatch(name, payload, ctx)`.
- **Capability cards** declare what each handler covers, what credentials it
  expects, and when it's relevant.
