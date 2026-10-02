# AGENTS.md — liminal

Instructions for AI coding agents working in this repo. Claude Code loads this via
`CLAUDE.md` (`@AGENTS.md`); other AGENTS.md-aware tools read it directly.

liminal is the tool gateway: handlers behind an MCP HTTP server, with JWT-scoped access
and per-caller allowlists.

## Build, test, lint

```bash
pip install -e ".[dev]"
pytest -q
ruff check src tests
```

`mypy` is configured `strict = true` and is a dev dependency, but **CI does not run it** —
only ruff and pytest. Do not assume a mypy failure blocks anything, and do not assume a
clean CI means the types check.

techne is optional. It backs the `memory` handler only, it is not on a public index, and
`tests/test_memory_handler.py` guards it with `importorskip`. Everything else, including
the rest of the suite, runs without it. **Never add a module-scope `import techne`.**

## The import trap, which has already produced a false bug report

`import liminal` resolves through whatever is *installed*, and this repo is normally
installed editable against the canonical checkout. So running `pytest` from a worktree or
a PR checkout can silently test **main** instead of the branch you are on — the tests
pass, and they passed against the wrong tree.

That produced a "the PRs are broken" report that was wrong (#83, #84). The fix is
`pythonpath = ["src"]` in `[tool.pytest.ini_options]`, which is now on main
(#88), so `pytest` run from a worktree imports that worktree's `src/`.

Outside pytest (a script, `python -c`, the `liminal` CLI) the editable install still
decides what `import liminal` finds. If you run those from anywhere other than the
canonical checkout, confirm you tested what you think you did, e.g.
`python -c "import liminal, sys; print(liminal.__file__)"`. And never "fix" a failing
import by reinstalling editable from whichever tree you happen to be in — that repoints
the install and hides the problem everywhere else.

## Releasing

There is no release workflow; tags are cut by hand. Bump `version` in `pyproject.toml`
in a PR, merge it, then tag **that** merge commit `vX.Y.Z` with the same number. v0.2.0
was tagged without the bump, so installs from it reported 0.1.0 (#95).
`tests/test_version_tags.py` fails when a reachable `v*` tag is newer than
`pyproject.toml`; it needs tags, so it skips in CI's shallow checkout and runs in a full
clone.

## Auth modes are exclusive, and the choice changes what you are touching

- `--jwks-url` — single-cabal: verify caller JWTs against one issuer's JWKS.
- `--trust-registry` + `--policy-db` — sovereign: multi-issuer, with a policy store.

Passing both is a hard CLI error. A change to claim handling almost always belongs to one
mode and not the other; say which in the PR.

`LIMINAL_AUTH_DISABLED=1` is the third state, for local use. It synthesises anonymous
claims with no `cabal_tool_extras`, so `ctx.extra` is empty. The `files` handler therefore
has no per-persona allowlist in that mode and takes its ceiling from
`LIMINAL_FILES_ALLOWED_PATHS` instead (#68). Unset, it still refuses everything — that is
the fail-closed default and it has not moved.

## Security defaults are load-bearing — do not widen them to make a test pass

- `handlers/files.py` ships with an **empty** allowlist: every read and write is refused
  until an operator supplies one. The empty default is the safe default.
- `handlers/web.py` denies the private ranges in `PRIVATE_NETWORKS` (10/8, 127/8,
  172.16/12, 192.168/16, fc00::/7, link-local) as SSRF defence, including the
  `::ffff:0:0/96` IPv4-mapped form.
- Untrusted tool results are wrapped, and the authority is `_meta["liminal/untrusted"]` —
  **not** the `[BEGIN UNTRUSTED TOOL RESULT]` banner text. The banner is what a human
  reads; the meta flag is what code must check. Do not "tidy" the wrapping logic without
  understanding which of the two a caller is relying on.

An agent that widens an allowlist to turn a red test green has reintroduced the
vulnerability the test exists to prove.

## Directory boundaries

```
src/liminal/
  protocol/    Handler Protocol, Context, ToolSpec, ToolResult, CapabilityCard
  registry/    Entry-point discovery and registration
  dispatch/    In-process dispatcher, multiplexer
  server/      MCP HTTP server, JWT verifiers, policy store, admin, secret guard
  target/      Federated targets (the `--targets` machinery)
  handlers/    THE EXTENSION SURFACE — scratchpad, files, web, memory, notify
  client/      MCPClient (sync) + AsyncMCPClient (async)
```

`handlers/` is where new capability goes. Everything else is gateway internals and should
not grow handler-specific branches.

A new handler registers through the `[project.entry-points."liminal.handlers"]` table in
`pyproject.toml` — not by editing the discovery code. Out-of-tree handlers register the
same way, which is the point of the seam.
