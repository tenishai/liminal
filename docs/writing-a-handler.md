# Writing a handler

The README's "Wiring a handler (custom)" section shows the mechanism: implement
`Handler` (or match its protocol — `tools()`, `dispatch()`, `capability_card()`),
register it via the `liminal.handlers` entry-point group. That covers how to get a
handler running. This page covers four things an author needs that aren't in the
README or `docs/design.md`, because they only show up in source.

## `ctx.extra` is the per-handler operator-config channel

Every shipped handler reads its own operator-supplied config out of
`ctx.extra` under a `<handler>.<setting>` key: `files.allowed_paths`,
`web.allowed_hosts`, `memory.db_path`, `notify.allowed_hosts`,
`notify.webhook_url`, `notify.transport`. There's no registration step for
this — a handler just reads `ctx.extra.get("<handler>.<setting>")` and falls
back to its own default (usually the safe/closed one) if the key is absent.
See `src/liminal/handlers/files.py`, `web.py`, `memory.py`, or `notify.py`
for the pattern in place.

**Security contract.** `ctx.extra` is populated differently depending on auth
mode, and the difference matters if your handler uses `extra` to pick a
*target* — a database, a path, a host. From `src/liminal/server/routes.py`
(around line 430):

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
config, but it is never caller input, and a handler must not treat it as
if the calling agent chose it.

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

## Testing convention

Every shipped handler has its own test module: `test_files_handler.py`,
`test_memory_handler.py`, `test_notify_handler.py`, `test_web_handler.py`,
`test_scratchpad.py`. There's no enforcement of this, but it's the
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
