# Writing a handler

The README's "Wiring a handler (custom)" section shows the mechanism: implement
`Handler` (or match its protocol — `tools()`, `dispatch()`, `capability_card()`),
register it via the `liminal.handlers` entry-point group. That covers how to get a
handler running. This page covers the things an author needs that aren't in the
README or `docs/design.md`, because they only show up in source.

## `ctx.extra` is the per-handler operator-config channel

Every shipped handler reads its own operator-supplied config out of
`ctx.extra` under a `<handler>.<setting>` key: `files.allowed_paths`,
`web.allowed_hosts`, `memory.db_path`, `notify.allowed_hosts`,
`notify.webhook_url`, `notify.transport`, `aws.roles`. There's no registration step for
this — a handler just reads `ctx.extra.get("<handler>.<setting>")` and falls
back to its own default (usually the safe/closed one) if the key is absent.
See `src/liminal/handlers/files.py`, `web.py`, `memory.py`, `notify.py` or `aws.py`
for the pattern in place.

**Security contract.** `ctx.extra` is populated differently depending on auth
mode, and the difference matters if your handler uses `extra` to pick a
*target* — a database, a path, a host. From `_handle_tools_call` in
`src/liminal/server/routes.py`:

> tool_extras carries per-persona SANDBOX config (memory.db_path,
> files.allowed_paths, web/notify.allowed_hosts, ...) that bounds where a
> handler may operate. In SOVEREIGN mode (a grant is present) the caller's
> cabal is NOT trusted, so its token-embedded tool_extras is IGNORED —
> otherwise a foreign token could pick which persona's memory DB / paths /
> egress a granted handler uses (the tenant-isolation seam). The sovereign
> service supplies these boundaries itself via `policy_tool_extras`
> (operator-configured), never the token. Single-cabal keeps the trusted
> token-embedded path (its issuer is also the policy authority).

In other words: `ctx.extra` is safe for a handler to trust as operator
config, and a handler must not treat it as if the calling agent chose it.
Two keys are exceptions, because routes.py copies them from request headers, so
they are caller input:

- `correlation_id`, from `x-correlation-id` (clamped to 200 characters), on every
  HTTP `tools/call`.
- `mcp.session_id`, from `Mcp-Session-Id` (clamped to 128 characters), only under
  `LIMINAL_AUTH_DISABLED=1` (#192). The scratchpad keys its buckets on it.

Use them to tell callers or traces apart, never as a path, host or authorization
input.

## `ctx.granted_scopes` and `ctx.audit` are for decisions the token must not make

`ctx.extra` comes from the token in single-cabal mode, so it cannot carry an
authorization decision. When a handler needs one inside a tool (the `files`
handler refusing CLAUDE.md and friends unless granted, #108), read
`ctx.granted_scopes` instead: routes.py fills it only from the server-side
policy grant, and it is empty in single-cabal, auth-off and library mode. Record
the decision with `await ctx.audit(allowed=..., detail={...})` when `ctx.audit`
is set (sovereign mode only; log it otherwise); it writes through `policy_store.record_access`, so it lands in the same
audit log as the route's own gates.

## Optional hooks: `startup()`, `shutdown()`, `status()`

None of these is part of the `Handler` protocol; liminal calls each one only if the
handler defines it (`src/liminal/target/inprocess.py`).

- `async startup()` / `async shutdown()` run in the app lifespan. `web` uses them to open
  and close a pooled HTTP client.
- `status() -> str | None` says whether the handler can serve without per-caller
  config. Return `None` when it can; otherwise return a sentence starting
  `unconfigured:` that names what to set. `/healthz` shows it in place of `ready`, and
  startup logs `liminal.handler_unconfigured` (#191). It does not mark the gateway
  degraded, because a token's tool extras may still supply the config. `files` and
  `memory` implement it. A `status()` that raises reads `status() failed: <type>`.

## Discovery is fail-open, and failure is silent

Per `src/liminal/registry/discover.py`: a handler whose import raises, or
whose `capability_card()` is malformed, is logged and skipped — other
handlers still register, so one broken handler doesn't take down the whole
tool surface. That's the right posture for the gateway, but it means: **if
your handler doesn't show up, it failed discovery, and there is no error
where you'd normally look for one.** Check the liminal server logs for a
`registry.*` warning, not a stack trace at startup.

## The per-tool `required_scope` footgun

`src/liminal/protocol/card.py` lets a capability card set `required_scope`
both at the handler level and per-tool. Per-tool wins — including when it's
*weaker* than the handler-level scope:

> FOOTGUN: per-tool wins even when WEAKER than the handler-level scope — a
> per-tool value can silently DOWNGRADE a tool below its handler's
> protection (there is no "max of the two"). Use this to REFINE (narrow) a
> handler scope, never to widen it.

Use per-tool `required_scope` to split a handler's tools into a stricter and
a looser group (e.g. memory recall vs. commit, files read vs. write) — never
to accidentally loosen a tool below what the handler already declares.

## Fields a room reads from your card

liminal checks a card's shape and passes the rest through: `labels` on the card
(strings only) and any extra key on a tool. `GET /admin/cards` on the admin plane
returns every loaded card as written. kobo reads four of these fields to work out
which handlers and scopes an agent's permissions open. A handler can then put a
vendor's tools in front of a room's agents with no change to the room:

- `labels.vendor`: the vendor whose permissions open this handler, as the room's
  permission catalogue names it (`gcp`, `okta`). No permission opens a card without
  one; only a grant someone writes by hand reaches that handler.
- `labels.audience: own-code`: only an agent that runs its team's own code may hold
  the handler. Use it when a tool hands a credential to its caller, because a model
  must never hold one.
- `permissions` on each tool: the catalogue permissions that open it. `["*"]` means
  any permission of the vendor. A tool with no `permissions` is opened by none.
- `risk` on each tool: `low` (reads, changes nothing), `write` (changes something a
  person can change back) or `irreversible` (cannot be undone).

Scopes still come from `required_scope`. For each tool a permission opens, the room
puts that tool's scope on the grant: the tool's own `required_scope`, or the card's
if the tool has none.

liminal enforces none of these fields, and a mistake in one does not make the card
invalid. Test them in your handler package.

## Testing convention

Every shipped handler has its own test module: `test_files_handler.py`,
`test_memory_handler.py`, `test_notify_handler.py`, `test_web_handler.py`,
`test_scratchpad.py`, `test_aws_handler.py`. There's no enforcement of this, but it's the
expectation — a new handler should ship with its own `tests/test_<name>*.py`
alongside it.

## cabal is the working out-of-tree example

`cabal` ships four handlers this way already — `patterns`, `documents`,
`code`, `archivist` — registered under the same `liminal.handlers`
entry-point group from `cabal`'s own `pyproject.toml`, as a separate
distribution from liminal itself. It's the proof that this seam works for a
real multi-handler package outside this repo, and it predates this doc.
Nothing here is duplicated in cabal — this is the one place the handler
contract is documented; cabal is where you can see it used.
