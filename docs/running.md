# Running the gateway (`liminal serve`)

Expose the handlers as one MCP endpoint any MCP client (Claude Code, goose, Cabal
personas) connects to. Handlers are **auto-discovered** from installed packages — install
`cabal` alongside liminal and its `patterns` / `documents` / `code` / `archivist`
handlers register automatically next to liminal's own seven.

```bash
# local / trusted-network — single operator on localhost, auth off:
LIMINAL_AUTH_DISABLED=1 liminal serve --host 127.0.0.1 --port 9100
# health check: curl http://127.0.0.1:9100/healthz (always 200 while serving; a
#   handler missing its server config reads "unconfigured: <what to set>", not "ready")
# readiness:    curl http://127.0.0.1:9100/readyz  (503 while any target is degraded)
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
# claim — it is not only a ceiling. `web` and `scratchpad` need no such grant.
# With auth off, liminal issues an Mcp-Session-Id on initialize and keeps each
# session's scratchpad apart; a client that sends none shares one bucket.
#
# `notify` has no JWT to carry a webhook URL in auth-off mode either, so the
# server's own config comes from the environment:
#   LIMINAL_NOTIFY_WEBHOOK_URL=https://ntfy.sh/my-topic   # used when a call names none
#   LIMINAL_NOTIFY_ALLOWED_HOSTS=ntfy.sh                  # host ceiling (default: any)
#   LIMINAL_NOTIFY_STDOUT=1                               # also offer `stdout`, off by default:
#                                                         # it writes caller text to this log
#
# POST /mcp refuses browser-shaped requests in every mode: an Origin that is not
# loopback gets 403, a Content-Type other than application/json gets 415. To let a
# browser UI on another origin through, list it (comma-separated, exact match):
#   LIMINAL_ALLOWED_ORIGINS=https://ui.example:8443

# production — verify caller JWTs against Cabal Core's JWKS (swap in your host).
# --host defaults to 127.0.0.1; 0.0.0.0 listens on every interface. (With
# LIMINAL_AUTH_DISABLED=1, serve refuses any non-loopback --host and exits 2, unless
# LIMINAL_AUTH_DISABLED_ALLOW_NONLOOPBACK=1 is set for a container whose port is
# published to loopback only.)
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

The single-cabal flags also read from the environment when absent — `LIMINAL_JWKS_URL`,
`LIMINAL_ISSUER`, `LIMINAL_AUDIENCE`, `LIMINAL_CABAL_URL`, `LIMINAL_TARGETS` — so a
container whose CMD is the bare `liminal serve` can be pointed at a cabal by its
deployment without rebuilding. A flag on the command line wins over the variable.

### Files that run on a common command (opt-in)

`files.write` always refuses files a tool runs with no command at all: `.envrc`, git hook
managers' configs, `.vscode/tasks.json` and the rest of the built-in list (issue #155,
tier 1). It does not refuse files that run when someone types a common command, such as
`conftest.py` (on `pytest`), `package.json` scripts (on `npm install`), `setup.py` (on
`pip install`) or a `Makefile` (on `make`). Agents edit these legitimately and often, so
refusing them by default would make the tool much less useful; but an agent steered by
injected content into writing one gets code run the next time anyone, or any CI job, runs
that command.

If your agents don't need to edit build and test configuration, refuse it too:

<!-- recipe:tier2 (tests/test_files_protected_writes.py reads this line) -->
```bash
LIMINAL_FILES_PROTECTED_PATTERNS=conftest.py:pytest.ini:tox.ini:noxfile.py:setup.py:setup.cfg:pyproject.toml:package.json:makefile:gnumakefile:justfile
```

Each name matches in any directory, case-insensitively, so `makefile` also covers
`Makefile`. The list adds to the built-ins and cannot remove any. A sovereign grant
holding `files:protected_writes` lifts it, as it does for the built-ins.

## Through Gojira

`gojira.yaml` at the repo root is the deploy contract for
[Gojira](https://github.com/tenishai/gojira): gateway class (one replica, the memory
handler's SQLite on the `liminal-data` PVC in `k8s/base`), port 9100, `/healthz`
(Gojira's gateway class uses one path for liveness and readiness, so the contract keeps
`/healthz`; `/readyz` is there for a deployment that probes readiness separately),
techne from a package index at build time, and the cabal it serves as `LIMINAL_*`
env. The Dockerfile takes the index token as a BuildKit secret
(`--secret id=ar_token`) and prefers it over `--build-arg AR_TOKEN`. Out of band per environment: Secret `liminal-secrets` with `LIMINAL_CABAL_TOKEN`
(`cbl token mint-service --scope secrets-fetch` on that cabal).
