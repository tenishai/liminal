# Welcome to liminal

liminal is an MCP gateway: an agent opens one MCP-over-HTTP connection to it and
reaches many tools behind it, from handlers running inside liminal and from other MCP
servers liminal forwards to. It decides per caller which tools are visible, holds the
sandbox limits for each, and fetches each persona's secrets at call time, so an agent
never holds them.

This guide ships in the package (`liminal guide welcome`). It describes the installed
version; `liminal version` says which one that is.

## Where it fits

| Project | Relationship | Required? |
|---------|--------------|-----------|
| techne | Backs the `memory` handler (the `[memory]` extra). | Optional. Without it `memory` refuses every call. |
| cabal | Mints the JWTs liminal verifies and publishes the JWKS for them, serves per-persona secrets at `/admin/secrets/{persona}/{handler}`, and ships four handlers (`patterns`, `documents`, `code`, `archivist`) through liminal's `liminal.handlers` entry points. cabal personas reach liminal through `liminal.client` (cabal's `[mcp]` extra). | Optional. Any RS256 JWT issuer works, and auth-off needs none. |
| daedalus | An agent runtime that uses liminal as its tool provider (`tools.provider: liminal`, or a `liminal.url` sidecar). | Optional consumer. |
| kobo | Drives a sovereign liminal's admin plane: writes each agent's grant (`/admin/policy/grant`), reads per-agent activity from the audit log (`/admin/policy/audit`), reads the loaded handlers' cards to work out what each permission opens (`/admin/cards`), and runs the AWS set-up checks (`/admin/aws/*`). It also bakes `liminal_url` into the bundles it composes. | Optional consumer. |
| gojira | Deploys liminal from `gojira.yaml` in the repo (gateway class, port 9100, `/healthz`). | Optional. |

liminal imports none of these at module scope. techne and botocore load lazily inside
their handlers.

## What it can do for you

- **Give an agent one tool endpoint.** `liminal serve`, then point the client at
  `http://127.0.0.1:9100/mcp` (Claude Code: `claude mcp add --transport http liminal
  http://127.0.0.1:9100/mcp`). Tools appear as `<handler>.<tool>`, e.g. `web.fetch`.
- **See what is installed.** `liminal list-handlers --cards` prints every handler the
  entry points found, with its tools and credential keys.
- **Add someone else's MCP server behind the same endpoint.** `liminal serve --targets
  targets.toml` (see "Federated upstream MCP servers").
- **Keep secrets out of agents.** `--cabal-url` makes liminal fetch each persona's
  credentials from cabal per call.
- **Serve several cabals from one gateway, with an audit trail.** Sovereign mode
  (`--trust-registry`), where every admitted call leaves an audit row.
- **Check health from a probe.** `GET /healthz` and `GET /readyz`.

## Options

### Auth mode: pick exactly one

| Mode | How | Reach for it when | Cost |
|------|-----|-------------------|------|
| Single-cabal | `--jwks-url <url>` (or `LIMINAL_JWKS_URL`), with `--issuer` (default `cabal-core`) and `--audience` (default `liminal`) | One issuer you trust mints every token, usually one cabal. | That issuer is the policy authority: the token's own `cabal_scope` (or `scope`) must hold `dispatch`, and its `cabal_tool_extras` (or `tool_extras`) set each caller's sandbox limits and handler allowlist. No audit rows, only log lines. |
| Sovereign | `--trust-registry registry.toml --policy-db policy.db` | Several independently run cabals share one gateway, or you want grants and an audit trail held server-side. | More to run: a registry file, a SQLite policy DB, and a grant for every persona (no grant means refused). Token scopes and extras are ignored, so sandbox limits come from the registry's one `[tool_extras]` table, the same for every caller. |
| Auth off | `LIMINAL_AUTH_DISABLED=1`, no verifier flags | One person on one machine, the client on the same host, liminal bound to `127.0.0.1`. | No identity: every caller is `anonymous`, operator-only tools are refused, `aws` has no accounts, and nothing can carry per-caller config, so `files`, `memory` and `notify` take theirs from `LIMINAL_*` variables. |

`--jwks-url` with `--trust-registry` is a CLI error (exit 2), and so is
`LIMINAL_AUTH_DISABLED=1` alongside a verifier. With no verifier and auth on, liminal
starts but refuses every `tools/list` and `tools/call`.

**When auth-off is acceptable.** Only on loopback, and liminal enforces it: with
`LIMINAL_AUTH_DISABLED=1`, `serve` exits 2 unless `--host` is `127.0.0.1` (or another
127.0.0.0/8 address), `::1` or `localhost`; `0.0.0.0`, `::`, a LAN IP or any other
hostname is refused. The one override is `LIMINAL_AUTH_DISABLED_ALLOW_NONLOOPBACK=1`,
for a container whose port is published only to loopback (`-p 127.0.0.1:9100:9100`);
it starts with a warning. The repo's Docker image runs `--host 0.0.0.0`, so under
auth-off it needs that override and that port mapping. The startup log prints a `liminal.AUTH_DISABLED` warning so
it is visible. Two guards stay on in every mode: `POST
/mcp` refuses an `Origin` that is not loopback (403; allow more with
`LIMINAL_ALLOWED_ORIGINS`, comma-separated) and any Content-Type other than
`application/json` (415), so a web page in your browser cannot reach the tools. A page
served from another loopback port still passes the Origin check. Under auth-off,
`initialize` hands each client an `Mcp-Session-Id`; a client that sends it back keeps
its own scratchpad, and one that doesn't shares a single bucket.

**Sovereign registry shape.** A top-level `service_audience`, then `[[issuer]]` tables
with `id` and `jwks_uri`. Exactly one sets `parent = true`, and it must list
`admin_personas`; serve exits 2 without them. Those personas, with a token from the
parent issuer, are the only callers of `/admin/*`: grant, revoke, list and audit, and
the live targets: `PUT /admin/targets/<name>` with a `[[target]]` body (minus `name`)
adds or replaces a federated target while serving, `DELETE` removes it, `GET
/admin/targets` lists live and file targets. Live targets persist in the policy
database and come back at boot; the targets file stays the seed and keeps its names.
`GET /admin/cards` lists every loaded handler's capability card, labels included.
`--admin-port` moves `/admin/*` to its own listener (bind with `--admin-host`, default
`127.0.0.1`) so a network policy can fence it. Without it the admin routes share the
data port, and liminal warns at startup.

**Standing-token exchange (off by default).** A caller normally trades its issuer's
long-lived standing token for a short one whose `aud` is this service, and presents the
short one. Add `exchange_uri = "https://issuer/its/exchange/route"` to an `[[issuer]]`
and callers from that issuer may present the standing token instead: liminal verifies
its signature and issuer, POSTs it to that route as a bearer, and uses the
`access_token` that comes back exactly as if the caller had sent it. The issuer keeps
its own gates, revocation included. An identity is reused for five minutes at most, so
that is how long a revoked standing token still works here; a refusal (401, 403) is
remembered for thirty seconds; an issuer that does not answer denies the caller. Turn
it on for callers that cannot reasonably write the trade and its refresh themselves,
and know the cost: the standing token then travels to liminal on every request, so
serve `/mcp` over TLS or keep it on a private network. liminal never logs or stores it.
Sovereign mode only; `--jwks-url` has no such option.

### Per-persona scoping

- **Which handlers a caller sees.** The `liminal.allowed_handlers` list in the token's
  tool extras (single-cabal), or `allowed_handlers` on the grant (sovereign). Absent
  means all handlers; present but empty or malformed means none. `tools/list` and
  `tools/call` apply the same filter.
- **Which tools need which scope** (sovereign only). Each handler card names scopes,
  such as `web:fetch` or `mem:append`, and the grant must hold them; `admin:*` holds
  every scope. `liminal serve` prints the handler-to-scope map at startup in this mode.
- **Credentials.** `--cabal-url http://cabal-core:7400` plus a token in
  `LIMINAL_CABAL_TOKEN` (minted with `cbl token mint-service --scope secrets-fetch`;
  `--cabal-token-env` renames the variable). liminal fetches `(persona, handler)`
  secrets per call and caches non-empty answers for `--cred-cache-ttl` seconds (default
  900). A failed fetch gives the handler empty credentials, not an error. In sovereign
  mode only the parent issuer's callers get credentials, because cabal's secrets path
  has no issuer in it and a foreign cabal could reuse a persona name.
- **Revocation.** With `--cabal-url` set, liminal also fetches that cabal's
  `GET /auth/revocations` (same `LIMINAL_CABAL_TOKEN` bearer) every `--revocation-ttl`
  seconds (default 30) and refuses a token from that cabal (in sovereign mode, the
  parent issuer) whose subject was revoked. It needs a cabal that serves the route
  (cabal 0.5.0); against an older cabal (404) or one that is down, tokens are accepted
  until `exp` as before, with one warning.

### Built-in handlers

All seven register whenever liminal is installed. A handler that refuses every call for
lack of server config still lists its tools.

| Handler | Tools | Configure it with | Reach for it when |
|---------|-------|-------------------|-------------------|
| `scratchpad` | `set`, `get`, `list`, `clear` | Nothing. | You want per-agent notes for one session, or to test a client end to end. In memory only: a restart wipes it. |
| `files` | `read`, `write`, `list`, `exists` | `LIMINAL_FILES_ALLOWED_PATHS` (absolute paths, `:`-separated), or `files.allowed_paths` in tool extras. The variable is the grant for a caller without the key and the ceiling for one with it. | An agent should read or write a fixed set of directories. Empty by default, so it refuses everything until you set one. Writes to agent instruction files (`CLAUDE.md`, `AGENTS.md`, `.mcp.json`, `.claude/`, `.git/hooks/` and more) need `files:protected_writes` on a sovereign grant; `LIMINAL_FILES_PROTECTED_PATTERNS` adds patterns. Reads cap at 1 MB. |
| `web` | `fetch`, `head` | `web.allowed_hosts` in tool extras narrows it; the default is any public host. | An agent needs to read public web pages or JSON. Private, loopback, link-local, CGNAT and cloud-metadata addresses are refused on every resolved IP, and the connection is pinned to the IP that was checked. 1 MB, 15 s, text-like content types only. |
| `memory` | `recall`, `commit` | The `[memory]` extra (techne), plus `LIMINAL_MEMORY_DB=/abs/path/memory.db`. A `memory.db_path` in tool extras may pick another file under that file's directory. | Agents should search and add to a shared techne knowledge store. Scopes `mem:query` and `mem:append` split read from write. |
| `notify` | `send`, `list_transports` | A webhook URL from the persona's cabal secret `NOTIFY_WEBHOOK_URL`, `notify.webhook_url` in tool extras, or `LIMINAL_NOTIFY_WEBHOOK_URL`. `LIMINAL_NOTIFY_ALLOWED_HOSTS` caps the hosts; `LIMINAL_NOTIFY_STDOUT=1` adds a log-only transport. | An agent should post to Slack, Discord, ntfy or any URL that takes a JSON POST. The URL must resolve to a public address. The stdout transport is off by default because it writes caller text into the server log. |
| `aws` | `whoami`, `call` | The `[aws]` extra (botocore), a `[tool_extras."aws.roles".<name>]` table with `role_arn` (and optional `audience`) per account, and a Google identity for the gateway (GCP metadata server, or a token file in `LIMINAL_AWS_WEB_IDENTITY_TOKEN_FILE`). | Agents need read-only AWS answers without holding keys. Each call assumes the account's IAM role with the gateway's own OIDC token and tags the session with the agent's name. Only read verbs pass, and data reads such as `s3:GetObject` or `secretsmanager:GetSecretValue` are refused by name. In sovereign mode a grant reaches account `<name>` when it holds `<name>:read`; without a grant (single-cabal or auth-off) every configured account is reachable, and the role's trust policy is the wall. |
| `cabal` | `agents`, `send`, `task`, `tasks`, `inbox`, `answer`, `cancel` | `--cabal-url` (or `LIMINAL_CABAL_A2A_URL`) and, in the caller's cabal secrets under handler `cabal`, one `CABAL_TOKEN_<AGENT>` dispatch token per persona it may call. | A person's own agent (Claude Code, goose, pi) should send tasks to cabal's personas and collect the results over MCP. `send` returns at once; poll `task`. Give the caller's token `--allowed-handler cabal` so it sees nothing else. Setup and revocation: `docs/cabal-handler.md`. |

The repo's Docker image includes the `[aws]` extra. A pip install without it makes every
`aws.*` call refuse with a sentence naming the extra.

`files`, `memory` and `notify` read their `LIMINAL_*` variables once, when the handler
is first built at startup.

Installing `tenish-cabal` next to liminal adds `patterns`, `documents`, `code` and
`archivist` the same way. Any package can add a handler through the `liminal.handlers`
entry-point group (see `docs/writing-a-handler.md` in the repo).

### Federated upstream MCP servers

`--targets targets.toml` (or `LIMINAL_TARGETS`) adds upstream MCP servers. Each
`[[target]]` has a `name` (its tools appear as `<name>.<tool>`) and an `address` (base
URL without `/mcp`). The file should start with `config_version = 1`. Only `transport =
"http"` is served; stdio entries validate but are refused at startup. Works in every
auth mode.

- `trust` defaults to `untrusted`: liminal scans the upstream's tool catalog for
  injection text and hidden Unicode (`on_untrusted = "flag" | "strip" | "block"`) and
  wraps results, flagging them in `_meta["liminal/untrusted"]`. A result with no content comes back with a notice saying so
  (it is not a confirmation) instead of an empty frame. Set `trusted` only for a
  server you run.
- `auth_method = "bearer"` sends a static token (`bearer_token` or `bearer_token_env`,
  `auth_scheme = "basic"` for Basic auth). `"service-token"` sends the calling persona's
  own credential named by `credential_key` on `Authorization`, so each persona
  authenticates as itself. `"service-headers"` does the same for upstreams that want a
  key pair in named headers instead: `[target.credential_headers]` maps each header name
  to a key in the persona's credentials (Datadog's hosted MCP server takes `DD_API_KEY`
  and `DD_APPLICATION_KEY`). A call missing any of them is refused, never sent bare.
- `[target.catalog_headers_env]` (with `service-token` or `service-headers`) names env
  variables whose values ride the catalog fetch alone (`initialize`, `tools/list`), for
  upstreams that refuse an unauthenticated catalog. They never ride a persona's call.
- `identity = "forward"` sends `x-liminal-persona` and `x-liminal-issuer`.
- `session = "per-persona"` holds one upstream session per caller, for servers that
  require `Mcp-Session-Id`.
- `required_scope` and `[target.tool_scopes]` gate the target's tools in sovereign mode.
  Naming any tool in `tool_scopes` makes that target's unnamed tools refused, unless a
  target-level `required_scope` is also set.

A target that fails to start or to fetch its catalog serves zero tools and shows as
degraded on `/healthz`; the other targets keep working. The full key list is the
`[[target]]` section of `docs/design.md` in the repo.

### The call audit log (0.7.0)

Every `tools/call` that reaches a handler logs one `tool.call` line in every mode:
persona, agent, issuer, handler, tool, a one-line argument summary (values clipped,
anything named like a secret masked, 300 characters at most), outcome, error text, and
milliseconds. In sovereign mode the same fields also go to the policy DB as an
`access_allow` row with `kind: call`, next to the refusals and grant changes already
recorded there. Read it with `GET /admin/policy/audit?persona=<p>&agent=<a>&since=<unix
ts>&limit=<n>` (limit up to 1000).

The table keeps the last 50,000 rows, so a busy gateway holds days, not months; ship the
`tool.call` log for anything longer. It is not tamper-evident. Single-cabal and auth-off
modes have no policy DB, so the log line is the only record.

### Health: `/healthz` and `/readyz`

Both return `{"status": "ok" | "degraded", "targets": {name: status}}`. A target reads
`ready`, a fixed failure such as `catalog fetch failed (startup)`, or, for `files` and
`memory` without server config, `unconfigured: <what to set>`. Unconfigured does not
count as degraded, because a token's tool extras may still supply the config.
`/healthz` always answers 200 (use it for liveness: a restart won't fix a dead upstream).
`/readyz` answers 503 while anything is degraded (use it for readiness).

### Other switches

- `LIMINAL_SECRET_GUARD=0` turns off the secret scan. It is on by default and refuses a
  `files.write`, `memory.commit` or `notify.send` whose content looks like a real key or
  token; placeholders such as `${VAR}` and `REDACTED` pass.
- `LIMINAL_JWKS_URL`, `LIMINAL_ISSUER`, `LIMINAL_AUDIENCE`, `LIMINAL_CABAL_URL` and
  `LIMINAL_TARGETS` stand in for their flags when a container's command can't change.
  A flag on the command line wins.
- `liminal.client` gives Python callers `AsyncMCPClient` and `MCPClient` for any MCP
  server, plus a library mode that calls handlers in-process. Library mode skips JWT,
  allowlists and the secret guard, so use it only inside a process you already trust.

### Extras

| Install | Adds | Reach for it when |
|---------|------|-------------------|
| `tenish-liminal` | The gateway and all seven handlers. | Always. |
| `tenish-liminal[memory]` | techne (`tenish-techne>=0.18.2`), for `memory`. | Agents should share a techne knowledge store. Install techne from the pin in `requirements-sources.txt`. |
| `tenish-liminal[aws]` | botocore, for `aws`. | Agents should read AWS accounts through roles. |
| `tenish-liminal[dev]` | pytest, ruff, mypy. | You are changing liminal itself. |

## How to install

The tenishai repos are private for now. Installing from the git URLs below needs a GitHub
account with read access to the tenishai organization, with git set up to use it (an SSH
key, or a token through a credential helper); without that, the install fails at the git
clone step.

From a tagged release:

```bash
pip install "tenish-liminal @ git+https://github.com/tenishai/liminal.git@v0.7.2"
```

With the memory handler, from a clone, so techne comes from its pinned tag:

```bash
pip install -r requirements-sources.txt ".[memory]"
```

The package also installs from the team's package index as `tenish-liminal`; the
Dockerfile's `EXTRA_INDEX_URL` build argument is how the image finds it. Python 3.12 or
newer. The import package and the command are both `liminal`.

A first run, local and auth-off:

```bash
LIMINAL_AUTH_DISABLED=1 LIMINAL_FILES_ALLOWED_PATHS=$HOME/scratch liminal serve
curl -s http://127.0.0.1:9100/healthz
```

## Where to go next

- `liminal guide` lists the bundled guides; this is the only one so far.
- `liminal serve --help` for every flag.
- In the repo: `README.md` ("Run the gateway" for a worked setup, "Through Gojira" for
  deployment), `docs/writing-a-handler.md` before you write a handler, `docs/design.md`
  for the `[[target]]` keys (the rest of it is the original proposal), `ARCHITECTURE.md`
  and `docs/arch/*.md` for how each part works, and `CHANGELOG.md` for what changed.
