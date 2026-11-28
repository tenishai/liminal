# Changelog

All notable changes to liminal are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); the project uses semantic versioning.
Each line cites the pull request that made the change.

## [Unreleased]

### Security

- **Credentials liminal sends to an HTTP target are masked out of what comes back** (#261). An upstream that echoed request headers, or a 5xx debug page, could hand the agent the persona's token. The per-call service-token or service-headers values, the static bearer, catalog headers and the catalog token are now replaced with `[redacted]` in the result and in upstream error text, including their base64, URL-encoded (either case of `%xx`), JSON-escaped and hex forms and the secret half of a Basic `user:secret`. A 5xx body is masked before it is cut to 200 characters, and untrusted results are masked again after hidden code points are stripped. Values under 8 characters are not masked. In-process handlers are not covered.

- **`files.write` refuses `.vscode/settings.json`** without the `files:protected_writes` grant (#155). Workspace settings can name executables VS Code and its extensions run, such as a linter's `executablePath`, and Restricted Mode does not apply in a folder the user has trusted. `.vscode/launch.json` and `.vscode/extensions.json` stay writable.

### Added

- **A documented `LIMINAL_FILES_PROTECTED_PATTERNS` recipe for build and test files** (#155, tier 2): `conftest.py`, `pytest.ini`, `tox.ini`, `noxfile.py`, `setup.py`, `setup.cfg`, `pyproject.toml`, `package.json`, `Makefile`, `GNUmakefile`, `justfile` and `.justfile` run code on a common command, so an operator whose agents don't edit them can refuse them. Opt-in and off by default; see docs/running.md. The `files` docstring says why they are not built in.

## [0.12.0] — 2026-11-28

### Changed

- **A pushed `vX.Y.Z` tag publishes the image `ghcr.io/tenishai/liminal`** (linux/amd64 and
  linux/arm64), after the whole CI, a native arm64 run and a vulnerability scan, and creates
  the GitHub release with an SBOM. `release.yml` is ported from cabal's; `test.yml` now accepts
  `workflow_call` so the release runs it on the tagged commit. Before this nothing published
  an image, so an install from released images had no liminal to pull.
- **CI: the `integration` job runs on every push and pull request, and `ci` requires it**
  (issue 115). It clones techne without a token, so it was dispatch-only while techne
  was private. It was never dispatched, so the techne-backed memory handler's tests had
  never run in CI. The test that pins `ci` now checks it fails when either job does not
  succeed.
- **techne pin moves from 0.18.2 to 0.20.0** (#259). `requirements-sources.txt` pins the
  `v0.20.0` tag, the `memory` extra needs `tenish-techne>=0.20.0`, and the Dockerfile's
  `TECHNE_VERSION`/`TECHNE_WHEEL_SHA256` name the v0.20.0 release wheel
  (`1e9371c5...`). A sibling-checkout build needs `../techne` at `v0.20.0`.
### Fixed

- **`/healthz` reports `notify` as `unconfigured` without a webhook URL** (issue 254). It
  said `ready`, but with no `LIMINAL_NOTIFY_WEBHOOK_URL` every `notify.send` that names no
  URL in its credentials or tool extras is refused. It now reads `unconfigured:
  LIMINAL_NOTIFY_WEBHOOK_URL is unset ...`, which, as for `files` and `memory`, does not
  make the gateway degraded, and startup logs `liminal.handler_unconfigured` for it.
- **Security: `files.write` refuses config that developer tools run with no command**
  (part of issue 155). Without the `files:protected_writes` grant it now refuses `.envrc`
  (direnv loads it on `cd`), `.vscode/tasks.json` (a `folderOpen` task runs when the
  folder opens), `.pre-commit-config.yaml`, every lefthook config name (`lefthook.yml`,
  `.lefthook.yaml`, `lefthook-local.json`, ... in any directory) and anything under
  `.husky/`. These are code-execution paths, like `.git/hooks`. Files that run on a common
  command (`conftest.py`, `Makefile`) stay writable; `LIMINAL_FILES_PROTECTED_PATTERNS`
  can add them.
- **`web` and `notify` no longer read proxy settings from the environment** (issue 204).
  With `HTTPS_PROXY` set, httpx sent pinned https requests through httpcore's proxy
  tunnel, which uses the pinned IP as the TLS server name, so certificate verification
  failed. Their clients now set `trust_env=False`: no env proxy, and no `SSL_CERT_FILE`
  or `SSL_CERT_DIR` either (the bundled certifi roots are used).

### Docs

- **RELEASING.md names the index in the resolve command** (#260).

### Upgrading

- **The image is now published:** `ghcr.io/tenishai/liminal:v0.12.0`, for linux/amd64 and linux/arm64. Installs that built their own image can pull it instead.
- **techne 0.20.0.** The `memory` extra needs `tenish-techne>=0.20.0`, and an image built from a sibling checkout needs `../techne` at `v0.20.0`. This is the techne cabal 0.5.1 pins, so the two now build together; liminal 0.11.0 pinned 0.18.2.
- **`web` and `notify` ignore `HTTPS_PROXY`, `HTTP_PROXY`, `SSL_CERT_FILE` and `SSL_CERT_DIR`.** A deployment that reached the internet only through an environment proxy, or trusted a private CA through `SSL_CERT_FILE`, now fails those calls. Give the gateway direct egress, or use a webhook and fetch targets the public roots verify.
- **`files.write` refuses more paths** without the `files:protected_writes` grant: `.envrc`, `.vscode/tasks.json`, `.pre-commit-config.yaml`, every lefthook config and anything under `.husky/`. An agent that wrote those needs the grant.
- **`/healthz` reports `notify` as `unconfigured`** when `LIMINAL_NOTIFY_WEBHOOK_URL` is unset. The gateway is not marked degraded by it, but a monitor that matched `notify: ready` will see the change.

## [0.11.0] — 2026-11-24

### Fixed

- **Security: liminal refuses tokens whose subject cabal has revoked** (issue 228, #245). It
  checked a cabal token's signature, `iss`, `aud` and `exp` but never cabal's revocation
  list, so after `POST /admin/token/revoke` a subject kept every tool that does not call
  cabal (`web`, `files`, `notify`...) until its token expired (a cabal service token can last up to 365 days). With
  `--cabal-url` set, liminal now fetches that cabal's `GET /auth/revocations` (new
  `--revocation-ttl`, default 30s) and refuses its tokens with `iat` before the subject's
  cutoff, as it refuses an expired token. Only that cabal's issuer is checked (in
  sovereign mode, the parent). Fail-soft: against an older cabal (404) or one that is
  down, tokens are accepted as before with one warning; a failed refresh keeps the last
  good list.
- **Security: `notify` refuses a webhook host that resolves to an IPv4 address embedded in
  IPv6.** The webhook check tested only the raw resolved address, so a host resolving to
  `64:ff9b::a9fe:a9fe` (NAT64), `2002:a9fe:a9fe::1` (6to4) or `::a9fe:a9fe`
  (IPv4-compatible), each carrying the cloud metadata address 169.254.169.254, or to a
  NAT64-wrapped private address such as `64:ff9b::a00:1`, passed. `web` already unwrapped
  these. Both handlers now use one address policy, `liminal/handlers/_netpolicy.py` (deny
  ranges plus embedded-IPv4 unwrapping), so the two checks cannot drift again (#242).

### Changed

- **`.gitignore` opens with a block shared by every tenish repo** (keys, env files, local databases, Terraform state, editor folders), with this repo's own lines under it (#250).
- **An empty result from an untrusted target now carries an explicit notice** (#233, fixed in #234). A federated upstream's result with no blocks, or only text that is blank once hidden Unicode is stripped, used to come back as a bare BEGIN/END marker pair, which the model could not tell from a refusal. The envelope now says the target returned no content and that this is not a confirmation, and `http_target.result_empty` is logged with the target and tool name. The nonce and `_meta` contract are unchanged.
- **Security: `liminal serve` refuses `LIMINAL_AUTH_DISABLED=1` on a non-loopback bind** (#214, #244). Auth off with `--host 0.0.0.0` used to start with only a warning, so anyone who could reach the port got every tool. Startup now exits 2 unless the host is 127.0.0.0/8, `::1` or `localhost`; any other value (`0.0.0.0`, `::`, a LAN IP, a hostname) counts as non-loopback. `LIMINAL_AUTH_DISABLED_ALLOW_NONLOOPBACK=1` overrides it, with a loud warning, for a container whose port is published to loopback only. **Breaking** for anyone running auth-off on a non-loopback bind; see Upgrading.
- **CI:** the Gojira-generated `.github/workflows/gojira-ci.yaml` is removed (#239). It deployed to the old dogfood install's cluster, which no longer exists, and it was the last workflow allowed a runner variable. `tests/test_ci_workflow.py` drops that exception. Adds `.github/CODEOWNERS`; since #247, Prudence (the project's AI code reviewer) owns everything except docs Markdown, so code changes need her review.
- **CI runs on GitHub-hosted runners.** `unit` and `integration` moved off the self-hosted runner, fork PRs run the unit suite (the `fork-pr` job is gone), and a `ci` summary job fails unless `unit` succeeded, so a skipped job cannot pass (#236, #237). A branch ruleset requires `ci` and `dco`.
- **Licence: MIT.** The project moves from AGPL-3.0-or-later to MIT, with the agreement of every contributor (tenishai/agora discussion 69). Releases already published keep the licence they shipped under (#235).
- **Docs:** README and docs corrected against the code (handler count, credential and wire-format claims, JWT issuer requirements, `labels` validation, stale CI text) (#241).
- **Docs:** a pre-release pass and a docs audit checked the README, the bundled guide and the agent-facing docs against the code (#246, #248, #251, #252); RELEASING.md records how a release is cut (#249); install wording stays true once the repos are public (#253); the README follows the outline the sibling repos share, with long sections moved to `docs/install.md`, `docs/running.md` and `docs/what-works.md` (#243).
- **ARCHITECTURE.md and CHANGELOG.md no longer name the maintainers' machines** (#238).

### Upgrading

- Revocation checking (`--revocation-ttl`, default 30s) takes effect only against a cabal that serves `GET /auth/revocations`, which is on cabal main after 0.5.0rc1 (tenishai/cabal pull request 455) and planned for cabal 0.5.0, not yet released when liminal 0.11.0 was. Against an older cabal (404) liminal logs one warning and accepts tokens until `exp` as before. It needs `--cabal-url` and the `LIMINAL_CABAL_TOKEN` bearer.
- A deployment that sets `LIMINAL_AUTH_DISABLED=1` with a non-loopback `--host` (including the Docker image's default `--host 0.0.0.0`) now fails at startup with exit 2. Bind `127.0.0.1`, configure a verifier, or set `LIMINAL_AUTH_DISABLED_ALLOW_NONLOOPBACK=1` and publish the port to loopback only (`-p 127.0.0.1:9100:9100`).

## [0.10.0] — 2026-11-19

### Added

- **`GET /admin/cards`: every loaded handler's capability card** (#232). The admin plane
  returns each handler's card under the name a grant's `allowed_handlers` and a tool name
  use. Fields a handler adds beside the schema's come back as written: the card's `labels`,
  and keys on a tool such as `permissions` and `risk`. A governing service can then work
  out what a grant opens from the handlers themselves. kobo uses it to derive which
  handlers and scopes each permission opens, instead of keeping a table of another
  install's handlers (docs/writing-a-handler.md, "Fields a room reads from your card"). An
  admin plane built without the registry answers 404, never an empty list, so a reader
  keeps what it knew. `create_admin_app` takes `registry=`, and `serve --admin-port`
  passes the registry it discovered.
- **`cabal` handler** (#189). A person's own MCP agent (Claude Code, goose, pi) sends tasks to
  cabal's personas and collects them: `cabal.agents`, `send`, `task`, `tasks`, `answer`,
  `cancel`, made as A2A v1.0 calls to `/agents/{agent}/a2a`. The caller's grant is its credential
  set, one `CABAL_TOKEN_<AGENT>` dispatch token per persona. `send` returns at once; a send that
  may have reached cabal without a reply returns `outcome: "uncertain"` with its contextId, which
  `tasks` settles. Setup and revocation: docs/cabal-handler.md.
- **`cabal.inbox`** (cabal#314). The tasks waiting on the caller (`input-required`) across every
  persona it holds a token for, newest first, each with the agent's question, a group task once.
  `contrib/claude-code/cabal_inbox_hook.py` prints them into a Claude Code session at start and
  when a new one arrives (docs/cabal-handler.md, "Inbox").
- **`exchange_uri` on a trust-registry issuer: liminal trades a standing token itself**
  (#227; sovereign mode, off by default). A caller that is a team's own code had to write the
  trade of its issuer's standing token for a short `aud`-scoped one, and the refresh, by
  hand. With `exchange_uri` set on its `[[issuer]]`, it presents the standing token and
  liminal makes the trade: only after the signature and issuer hold (`AudienceError`),
  POSTed as a bearer, the answer verified in full, the identity reused for five minutes at
  most. The trade hands a caller nothing it could not fetch with one request of its own.
  What changes is that the standing token reaches liminal, so it is opt-in per issuer and
  the guide says what it costs. A registry without the key behaves as before.

### Changed

- `serve --cabal-url` exports `LIMINAL_CABAL_URL` before handler discovery when the variable is
  unset, so handlers that read it (the cabal handler) get the flag's value.

### Upgrading

- An embedding that builds its admin listener with `create_admin_app` passes `registry=`
  (the data plane's) to serve `GET /admin/cards`; without it that route answers 404.
  `liminal serve` already does.
- The `cabal` handler ships in liminal's own entry points, so every install now loads it. A
  persona whose grant allows every handler (`allowed_handlers` unset) also sees `cabal.*`.
  Those tools refuse every call until `LIMINAL_CABAL_A2A_URL` or `LIMINAL_CABAL_URL` is set
  and the caller holds a `CABAL_TOKEN_<AGENT>` credential.

## [0.9.3] — 2026-11-01

### Fixed

- **`ToolCallOutcome.text` includes embedded resources** (#226). A file a server returns as an
  MCP `EmbeddedResource` (GitHub's hosted server answers `get_file_contents` with a one-line text
  block and the file as a resource) was dropped by the text-only flattening, so a runtime that
  reads `outcome.text` handed the model "successfully downloaded text file" and no file. The
  resource's text now follows a line naming its uri and type; a binary resource is named, not
  expanded. Found by the kobo agent-layer wire test on 2026-10-31.

## [0.9.2] — 2026-10-31

### Added

- **`catalog_token_provider`: a bearer for the catalog fetch, minted on demand** (#225).
  GitHub's hosted MCP server refuses an unauthenticated `initialize` and wants the
  credential on `Authorization`, which `catalog_headers_env` may not set (liminal owns
  that header), so a `service-token` target for it had no way to list tools without a
  long-lived personal token in an env var. A target now names a provider from the new
  `liminal.catalog_tokens` entry-point group; `HttpTarget` awaits it before every catalog
  fetch (startup and each refresh) and sends the token on the catalog client's requests
  alone, encoded with `auth_scheme`. A deployment mints what it likes (a one-hour GitHub
  App installation token) and nobody rotates anything. Persona sessions and calls are
  untouched: they carry the persona's own credential or are refused, as before. An unknown
  provider, or one that returns an empty token, fails the target's startup naming it; a
  mint that fails on refresh is a failed refresh, and the last good catalog keeps serving.

## [0.9.1] — 2026-10-31

### Fixed

- **A per-persona session an upstream reports lost through a JSON-RPC error is reopened**
  (#224). The streamable-HTTP spec says a gone session is a 404, which liminal already
  reopens once; Datadog's hosted MCP server instead answers a call that carries no usable
  `Mcp-Session-Id` with HTTP 200 and a JSON-RPC error `[0] missing session ID`, which
  liminal returned to the agent as a tool error on every call after the first. Two
  remedies, both in `HttpTarget._call_in_session`: a JSON-RPC error whose message says the
  session is missing, unknown, expired or invalid forgets the session
  (`AsyncMCPClient.forget_session`), reopens it with the persona's own credential and
  retries once, the same as a 404, and a second loss is the error it was; and a
  session-keeping client that is initialized but holds no session id
  (`AsyncMCPClient.has_session`) is reopened before its call instead of calling bare,
  logged as `http_target.session_missing`. The live gateway showed exactly that shape (one
  good call, then every later call bare); what dropped the id in that process is not yet
  known, and the log line is there to catch it.

## [0.9.0] — 2026-10-30

### Upgrading

- Nothing to run. With `--policy-db` the gateway creates a `live_targets` table in that
  database on first boot. Without a policy DB nothing changes.

### Added

- **Targets through the admin plane** (#222, #223). `PUT /admin/targets/{name}` with a
  `[[target]]` body (the same keys the targets file takes, minus `name`), `DELETE
  /admin/targets/{name}` and `GET /admin/targets`, for the same parent admin personas
  the policy routes take. A PUT validates the spec, starts the target (catalog fetch
  included), lets it take the name and shuts down the one it replaced; a DELETE shuts
  it down and drops it; both persist in the policy database so the target comes back
  at the next boot. `targets.toml` stays the seed and keeps its names: a live target
  may not take a handler's or a file target's name (409), and a stored row the file
  later shadows is skipped with a warning, never a boot failure. No secret travels in
  a spec (`bearer_token` is refused; env variable names and per-call credentials are
  the ways in). `required_scope` and `tool_scopes` on a live target are enforced like a
  file target's. A room that connects a vendor can now add its MCP server to the
  gateway the moment the credential is accepted, with no pull request and no redeploy.

## [0.8.0] — 2026-10-30

### Upgrading

- Nothing to run. Two new `[[target]]` keys, both optional; existing target files load
  unchanged.

### Added

- **`auth_method = "service-headers"`: a persona's leased credentials as named headers**
  (#221). `[target.credential_headers]` maps each header name to a key in the calling
  persona's `ctx.credentials`; every call sends every header, built fresh per call like
  service-token's `Authorization`, and a call missing any of them is refused rather than
  sent bare (the #80 guarantee). For upstreams that authenticate with a key pair rather
  than a bearer token: Datadog's hosted MCP server takes `DD_API_KEY` and
  `DD_APPLICATION_KEY`, and a permission service can lease the application key per
  agent. Names are checked like static `headers` (valid field names, case-insensitive,
  `Authorization` and liminal's own headers reserved) and may not repeat a static one.
- **`[target.catalog_headers_env]`: headers for the catalog fetch alone** (#221). Env
  variable names, read at startup like `bearer_token_env` (unset or empty fails the
  target's startup, naming the variable), sent on `initialize` and `tools/list` only and
  never on a persona's call or session. For `service-token` and `service-headers`
  targets, whose catalog fetch otherwise goes out unauthenticated, against upstreams that
  refuse it. The `liminal guide welcome` target section and `docs/design.md` describe
  both keys.

## [0.7.2] — 2026-10-27

### Fixed

- **The `aws` handler never completed a real assume** (#217). `AssumeRoleWithWebIdentity`
  takes no `SourceIdentity` parameter (that belongs to `AssumeRole`), and botocore refused
  it before the call left the gateway, so every `call` and `whoami` failed with a 500 once a
  role was configured. The agent's name now travels only in `RoleSessionName`
  (`kobo-<agent>`), which CloudTrail records in the assumed-role ARN. A client-side botocore
  failure is now an `AwsError` the agent can read instead of a traceback. Found when the
  same code made its first live call from bab.

## [0.7.1] — 2026-10-26

### Upgrading

- Nothing to run. The Docker image now also installs botocore, through the `[aws]`
  extra. A pip install from git is unchanged unless you ask for `[aws]`.

### Added

- **`liminal guide` prints the guides that ship in the package.** With no name it lists
  them; `liminal guide welcome` prints the welcome guide, which says what liminal is,
  which projects use it, and each auth mode, handler, extra, `LIMINAL_*` variable and
  endpoint with when to pick it and what it costs. An unknown name exits 2 and lists the
  valid ones (#213). The markdown lives in `src/liminal/docs/` and rides in the wheel as package
  data, so an installed liminal can explain itself without the repo.
  `tests/test_bundled_docs.py` fails when a guide is missing from disk or from
  package-data, or when the welcome guide lacks a row for a built-in handler or extra.

### Fixed

- **The Docker image installs the `[aws]` extra**, so the `aws` handler can make calls in
  liminal's own image. Before, every `aws.*` call there refused for want of botocore (#213).

- **Docs caught up with 0.6.0 and 0.7.0.** README and AGENTS.md counted five built-in
  handlers and left out `aws`; README now names it and the per-call audit, and has a
  "Where this fits" section. `docs/writing-a-handler.md` adds the `aws.roles` key, the
  optional `startup`/`shutdown`/`status` hooks, and `mcp.session_id` as caller input
  beside `correlation_id`. The repo card said 0.7.0 was the aws release; `docs/design.md`'s
  health section now mentions `unconfigured:` handlers. `liminal serve --help` documents
  `--host` and `--port` (#213).

## [0.7.0] — 2026-10-26

### Upgrading

- **The audit table grows with every admitted call.** It was refusals only; it is now one
  row per `tools/call` a grant admitted. The ring buffer still prunes at 50k rows, so a busy
  gateway keeps roughly its last few days; ship the `tool.call` log line to wherever logs
  live for the long tail.

### Added

- **Every call that reaches a handler leaves one audit row** (for kobo's per-agent
  activity view). The gateway used to record refusals only, so an allowed call left no
  trace beyond the handler's own logs. Now each `tools/call` that a grant admitted writes an
  `access_allow` row with `kind: call`, the handler and tool, a one-line argument summary
  (keys in order, values clipped, anything named like a secret masked, 300 characters at
  most), the outcome, the error's first 200 characters, the duration in milliseconds and
  the inbound correlation id; and in every auth mode it logs one `tool.call` line with the
  same fields. `GET /admin/policy/audit` takes `persona=` and `agent=` filters and caps
  `limit` at 1000. Handlers that write their own rows (files) are unchanged; their rows
  carry no `kind`.

## [0.6.0] — 2026-10-25

### Upgrading

- **The `aws` handler needs the `[aws]` extra to make calls** (tenishai/liminal#209). An
  image that installs `tenish-liminal` without it still starts and lists the handler; every
  `aws.*` call then refuses with a sentence naming the extra. Install `tenish-liminal[aws]`
  where agents are meant to reach AWS, and give the gateway a Google identity (a service
  account linked to its Kubernetes service account) before naming it in any role's trust
  policy.

### Added

- **An `aws` handler: read-only AWS calls through a role the account owner granted the
  gateway** (tenishai/liminal#202, first kind). No access key anywhere: the owner creates
  one IAM role per account (tenishai/cloud-access `KoboAccess-Role`) whose trust policy names
  the gateway's own Google service account through OIDC; per call the gateway mints a Google
  ID token for itself, trades it for a one-hour session with `AssumeRoleWithWebIdentity`
  tagged with the agent's name as `SourceIdentity`, and runs the read. Accounts are
  operator config, `[tool_extras."aws.roles".<name>]` with `role_arn` (and an optional
  `audience`, default `sts.amazonaws.com`); an agent reaches an account when its grant holds
  `<name>:read`. Only read verbs are forwarded and a short list of data-plane reads (object
  bodies, secret and parameter values, table rows, queue messages) is refused by name,
  whatever the role allows. Tools `aws.whoami` and `aws.call`; scope `aws:read`. Installs
  botocore through the new `[aws]` extra; without it the handler registers and refuses calls
  with a sentence naming the extra. Two admin routes for a set-up page: `GET
  /admin/aws/identity` says the issuer, subject and audience a trust policy must name, and
  `POST /admin/aws/probe {role_arn, audience?}` assumes a role once as the room so
  "connected" is said only after AWS agreed.

### Changed

- **The generated Gojira CI checks the manifests build before it applies them**
  (tenishai/liminal#182). `gojira-ci.yaml` runs `kubectl kustomize .` first, so a
  manifest that does not build fails once with kustomize's message instead of going
  through the apply retries meant for a cold cluster.

### Fixed

- **`/healthz` says which handlers are unconfigured** (tenishai/liminal#191, partly). A
  handler that refuses every call for want of server config reported "ready", and on a workstation
  14 of 25 advertised tools always refused. A handler may now define an optional
  `status()`; `/healthz` shows its answer, e.g. `unconfigured: LIMINAL_FILES_ALLOWED_PATHS is
  unset`, and startup logs `liminal.handler_unconfigured` for each; a `status()` that raises
  reads `status() failed: <type>`. `files` and `memory` implement it. It does not make the
  gateway degraded or `/readyz` fail, and the tools stay listed, because under auth a
  token's claims can supply what the server lacks. cabal's handlers implement it from
  tenishai/cabal#379.
- The auth-off startup banner no longer says only browser-origin and non-JSON requests are
  refused; operator-only tools are refused too (tenishai/liminal#199).
- **With auth off, each MCP session has its own scratchpad** (tenishai/liminal#192). Every
  auth-off caller is `anonymous`, so all sessions shared one bucket: one session's
  `scratchpad.set` overwrote another's, and any `scratchpad.clear` wiped everyone's. Under
  auth-off, `initialize` now answers with an `Mcp-Session-Id` header, clients send it back,
  and the scratchpad keys on it. A client that sends none still shares the old bucket. Under
  auth nothing changes: the header is neither issued nor read.
- **`notify` can be configured with auth off, and `stdout` is opt-in**
  (tenishai/liminal#197). With no JWT the webhook transport had no URL and always failed,
  and the one transport that worked, `stdout`, let any caller write multi-line text,
  fake `[warning]` lines included, into liminal's own log. The server now reads
  `LIMINAL_NOTIFY_WEBHOOK_URL` (used when a call names none) and
  `LIMINAL_NOTIFY_ALLOWED_HOSTS`, offers `stdout` only with `LIMINAL_NOTIFY_STDOUT=1`, and
  writes each `stdout` notification as one line.
- **`web.fetch`, `web.head` and `notify` pin https to the validated IP, and pin IPv6
  correctly** (tenishai/liminal#196, tenishai/liminal#195). https requests were left
  unpinned, so a rebinding DNS name could steer the TCP connect and TLS handshake to an
  internal address and tell open from closed ports by the error. Now both schemes connect to
  the IP the SSRF check validated: the URL carries the IP, `Host` keeps the original name
  (with a non-default port, which it used to drop), and for https the `sni_hostname`
  extension makes TLS send that name and verify the certificate against it. A pinned https
  request uses its own client, because the shared pool is keyed by IP and would reuse a TLS
  session verified for another name. An IPv6 first address used to build an invalid URL
  (`InvalidURL: Invalid port`); it is now bracketed.
- **`files.read` reads at most one byte past its cap** (tenishai/liminal#194). It
  used to load the whole file and then slice it, so one read of a large log in an
  allowlisted directory could exhaust the memory of the process every handler shares.
  `max_bytes` is now clamped to `1..max_read_bytes` (`-5` used to cut the tail off the
  file and report `truncated: true`; `0` used to mean "the handler's cap" and now reads
  one byte), and a value that is not an integer, including the string `"10"` that
  used to be coerced, returns a failure naming `max_bytes`. `files.list` stops reading
  the directory once it has one entry past its cap instead of sorting the whole
  directory first. The entries it returns are still sorted by name, so a listing under
  the cap is unchanged; a truncated listing now holds the first entries the filesystem
  returns, not the alphabetically first.
- **A handler's exception reaches the agent with an error id it can report**
  (tenishai/liminal#193). The failure used to say only `web.fetch raised ValueError`,
  and the operator had to find the log line by timestamp. It now reads
  `web.fetch raised ValueError (error id 1a2b3c4d)`, and the `multiplexer.target_raised`
  (or `dispatch.handler_raised`) log line carries the same `error_id` next to the
  exception's message, which still stays out of the result. liminal's own handlers
  also check argument types instead of raising: `web.fetch` `max_bytes` and
  `memory.recall` `limit` must be integers and `files.write` `create_parents` a
  boolean, and a wrong type returns a failure naming the field. `max_bytes` and
  `limit` are clamped to 1 and up (`max_bytes: -5` used to cut the tail off the body),
  so `0` now means one byte or one hit rather than the default; the string
  `"false"` for `create_parents` used to mean true. `files.read` `max_bytes` is
  covered by tenishai/liminal#194.

- **`POST /mcp` refuses requests from a browser page** (tenishai/liminal#190). A page
  in the operator's browser could call every tool on a loopback liminal running with
  `LIMINAL_AUTH_DISABLED=1`, by posting a `text/plain` body (no CORS preflight) or by
  rebinding its own domain to 127.0.0.1. The route now answers 403 to an `Origin` that
  is not loopback or listed in the new `LIMINAL_ALLOWED_ORIGINS`, including `null`, and
  415 to a Content-Type other than `application/json`. Clients that send no `Origin`
  (Claude Code, cabal, curl with `-H 'Content-Type: application/json'`) are unaffected.

- **The Docker image reads the private index token from a BuildKit secret**
  (tenishai/liminal#177). The generated `gojira-ci.yaml` now passes it as
  `--secret id=ar_token` instead of a build arg, which the build log prints
  (tenishai/liminal#176). The Dockerfile only read the build arg, so every Gojira build
  since that change had no credential for the index and stopped at pip's password
  prompt. The venv step now mounts the secret and prefers it; `--build-arg AR_TOKEN=…`
  still works for a local build.

## [0.5.0] — 2026-10-13

### Upgrading

- **Target `headers` are checked against HTTP's rules at load** (tenishai/liminal#141).
  A header name with spaces (surrounding ones included), a colon or another character
  outside the RFC 9110 token set, or a value containing CR, LF or NUL, now stops
  `liminal serve` at startup with a message naming the header. Such a config used to load
  and then fail on the first request to that target, so no working config is refused.

### Added

- **Stateful upstream MCP servers can be targets** (tenishai/liminal#172). A server that
  returns an `Mcp-Session-Id` on `initialize` and refuses later requests without it used
  to leave its target with no tools and `catalog fetch failed (startup)` on `/healthz`.
  Set `session = "per-persona"` on the target: each calling persona, keyed by verified
  issuer and identity, gets its own upstream session opened with its own credential, and
  the catalog fetch gets a separate one, so a session id never rides another persona's
  call. An expired session (404) is reopened once, and shutdown ends every session the target still holds. The
  default, `session = "none"`, is unchanged: no session id is kept or sent.
- **`GET /readyz`** (tenishai/liminal#159) returns the `/healthz` body with status 503
  while any target is degraded, for a readiness probe that should take the gateway out of
  service when an upstream is down. `/healthz` still answers 200 for liveness.
- `AsyncMCPClient.initialize(extra_headers=)`, `AsyncMCPClient.terminate_session()`, the
  `initialized` property, and `MCPSessionExpired` (a subclass of `MCPTransportError`,
  raised on a 404 to a request that carried a session) in `liminal.client`.

### Known limitations

- A persona session evicted by the 256-session cap is not ended with `DELETE`; it
  expires on the upstream's own clock (tenishai/liminal#174).
- Shutdown sends its `DELETE`s one after another, each bounded by the target's
  `timeout_seconds`, so an upstream that accepts connections and then hangs can slow
  shutdown (tenishai/liminal#174).

### Tests

- A sentinel-credential test asserts that no request made for one persona carries
  another persona's credential or session id (tenishai/liminal#93). The issue's audit of
  every pattern match on the authorization boundary is recorded in `docs/arch/policy.md`.

## [0.4.1] — 2026-10-12

### Upgrading

- **The old distribution names get no further releases.** liminal is published only as
  `tenish-liminal` from 0.4.0 on; `liminal` (0.2.0 and earlier) and `tenishai-liminal`
  (0.3.0) stop where they are. A requirement on either old name, from git or from a
  private index, has to change to `tenish-liminal`; uninstall the old name first, because
  pip treats the names as unrelated projects. The import package and the `liminal`
  command are unchanged.

### Added

- **A target can send its credential as HTTP Basic, and read it from the environment**
  (tenishai/liminal#170, a port of Kyle Greiner's tenishai/liminal#89). `auth_scheme`
  is `"bearer"` (the default, unchanged behaviour) or `"basic"`, which sends
  `Authorization: Basic base64(<value>)` with the value as `user:secret`, on every call
  to the upstream: initialize, notifications, the tool catalog and tool calls, and the
  per-call header of a `service-token` target. `bearer_token_env` names an environment
  variable that holds the static credential, so it stays out of the targets file; it is
  mutually exclusive with `bearer_token`. An unset, empty or whitespace-only variable
  stops `liminal serve` at startup with a message naming it, and an unknown
  `auth_scheme` is refused. A v0.4.0 server refused both keys as unknown.

### Changed

- **`bearer_token_env` without `auth_method = "bearer"` is refused at load**
  (tenishai/liminal#171). The key is read only for bearer targets, so accepting it with
  any other `auth_method` would have left the target calling its upstream anonymously.
  No release accepted it that way: 0.4.0 refused the key as unknown.

## [0.4.0] — 2026-10-12

### Upgrading

- **The distribution is now `tenish-liminal`** (was `tenishai-liminal`, tenishai/liminal#169). The import
  package and the `liminal` command are unchanged. Run `pip uninstall tenishai-liminal`
  before installing 0.4.0: pip treats the two names as unrelated projects and would leave
  both installed. A dependency written as `tenishai-liminal>=0.3` becomes
  `tenish-liminal>=0.4`. An editable checkout must be reinstalled
  (`pip install -e ".[dev]"`); until then `liminal version` reports `0.0.0+unknown`,
  because `liminal.__version__` looks up only the new name. `v0.4.0` is the first tag that
  builds `tenish-liminal`; `v0.3.0` builds `tenishai-liminal`.
- **techne 0.18.2, under its new distribution name `tenish-techne`** (tenishai/liminal#158).
  The `memory` extra needs `tenish-techne>=0.18.2`, `requirements-sources.txt` pins the
  `v0.18.2` tag, and the Dockerfile's index path downloads `tenish-techne==0.18.2` and
  checks its wheel hash. The import package and the `techne` command are unchanged. Run
  `pip uninstall techne` first: pip treats the two names as unrelated projects and would
  leave the old one installed beside the new one. A sibling-checkout image build wants
  `../techne` at `v0.18.2`; `bash scripts/check-techne-sibling.sh` checks it.
- **`liminal serve` reads `LIMINAL_JWKS_URL`, `LIMINAL_ISSUER`, `LIMINAL_AUDIENCE`,
  `LIMINAL_CABAL_URL` and `LIMINAL_TARGETS` when the matching flag is absent**
  (tenishai/liminal#153). A server whose environment already sets one of them now uses
  it. `LIMINAL_JWKS_URL` set beside `--trust-registry` is the single-cabal/sovereign
  conflict, and `liminal serve` exits 2. A flag on the command line still wins, and an
  empty variable counts as unset.

### Added

- **`liminal serve` takes its single-cabal settings from the environment.** `--jwks-url`,
  `--issuer`, `--audience`, `--cabal-url` and `--targets` default to `LIMINAL_JWKS_URL`,
  `LIMINAL_ISSUER`, `LIMINAL_AUDIENCE`, `LIMINAL_CABAL_URL` and `LIMINAL_TARGETS`, so a
  container whose CMD is the bare `liminal serve` can be pointed at a cabal by its
  deployment without a rebuilt image (tenishai/liminal#153).
- **Gojira deploy config.** `gojira.yaml` is the deploy contract for Gojira (gateway class,
  port 9100, `/healthz`, techne from a package index at build time, the cabal as
  `LIMINAL_*` env, `LIMINAL_CABAL_TOKEN` from the `liminal-secrets` Secret); `k8s/base`
  holds the memory handler's `liminal-data` PVC beside the generated Deployment, Service,
  PodMonitoring and rules, with a `dev` overlay and the generated
  `.github/workflows/gojira-ci.yaml` (tenishai/liminal#153, tenishai/liminal#160,
  tenishai/liminal#164). The README has a "Through Gojira" section.
- **A caller with no policy grant is logged as well as audited.** In sovereign mode the
  no-grant denial now logs a warning `access.denied` with the issuer, persona, agent and
  reason (never the token) beside its `access_deny` audit row (tenishai/liminal#167, closes
  tenishai/liminal#166).

### Changed

- **The distribution is named `tenish-liminal`** (was `tenishai-liminal`): every released
  tenish Python distribution is named `tenish-<project>`, as techne is `tenish-techne`.
  pyproject's `name`, `liminal.__version__`'s lookup, the README install line and the
  repo card change; the import package, the CLI and the GitHub URL
  (`github.com/tenishai/liminal`) do not (tenishai/liminal#169).
- **techne is pinned at 0.18.2 under its new name, `tenish-techne`**, in pyproject's
  `memory` extra, `requirements-sources.txt`, the Dockerfile (`TECHNE_VERSION`,
  `TECHNE_WHEEL_SHA256`) and `tests/test_techne_pin.py` (tenishai/liminal#158).
- **The copyright holder is "tenish and the liminal contributors"** in NOTICE and the
  README, and pyproject's `authors` is `tenish`. The licence (AGPL-3.0-or-later) is
  unchanged (tenishai/liminal#157).
- **The README says how liminal was built, and CONTRIBUTING.md gives the policy for
  AI-assisted contributions** (tenishai/liminal#162).

### Tests

- **Every workflow is checked for fork access to the self-hosted runner**
  (tenishai/liminal#163, a port of tenishai/cabal#262). A self-hosted job must carry the
  fork guard unless its workflow triggers only on push and `workflow_dispatch`, and a
  runner label that is not a GitHub-hosted one counts as self-hosted. This replaced a
  check that failed on any second workflow, which Gojira's generated `gojira-ci.yaml`
  (tenishai/liminal#160) had broken.

## [0.3.0] — 2026-10-03

### Upgrading

- **Sovereign mode: only the parent issuer's callers get credentials** (tenishai/liminal#148,
  closes tenishai/liminal#143). A caller from any other trusted issuer now gets empty
  credentials. `service-token` HTTP targets refuse it; notify's webhook refuses it unless
  the operator has set `notify.webhook_url` in its tool extras. A custom `credential_resolver` used in sovereign mode must accept an `issuer`
  keyword argument.
- **`notify`'s result no longer carries the webhook URL** (tenishai/liminal#150, closes
  tenishai/liminal#149): a successful send returns `host` in place of `url`.
- **The distribution is now `tenishai-liminal`.** The import package and the `liminal`
  command are unchanged. Run `pip uninstall liminal` before installing 0.3.0: pip treats
  the two names as unrelated projects and would leave the old one in place. A dependency
  written as `liminal>=0.1` becomes `tenishai-liminal>=0.3`. `v0.3.0` is the first tag
  that builds `tenishai-liminal`; `v0.2.0` builds `liminal` (and reports version 0.1.0,
  tenishai/liminal#95) and `v0.1.0` builds `limenal`.
- **techne 0.18.0.** The `memory` extra needs `techne>=0.18.0`, and
  `requirements-sources.txt` pins the `v0.18.0` tag (tenishai/liminal#133). An image
  built from a sibling checkout wants `../techne` at that tag:
  `bash scripts/check-techne-sibling.sh` checks it, and `TECHNE_ANY=1` (script) or
  `--build-arg TECHNE_ANY_VERSION=1` (build) skips the check.
- **A policy DB whose parent rows name an issuer that is no longer the configured parent
  refuses to open** (tenishai/liminal#134). `liminal serve` exits 2 and names the issuer.
  Point `--policy-db` at a new database to adopt the configured parent.
- **`files.write` now refuses protected paths, none of which 0.2.0 protected**
  (tenishai/liminal#109, tenishai/liminal#120, tenishai/liminal#137): agent instruction
  files (CLAUDE.md, AGENTS.md and other tools' equivalents), code-execution paths (`.git`,
  `.mcp.json`, `.claude.json`, `.vscode/mcp.json`, `.gemini/` and more), and any regular
  file with more than one hard link. Only a sovereign-mode grant holding
  `files:protected_writes` lifts the refusal; in auth-off and single-cabal modes these
  paths cannot be written through `files.write`. `LIMINAL_FILES_PROTECTED_PATTERNS` adds
  operator patterns.
- **A `[[target]]` that still sets `relevance_signals` is an unknown-key error**
  (tenishai/liminal#136). Delete the key; nothing read it.
- **An SSE server that holds its stream open after the reply adds up to 0.5 s per call**
  (tenishai/liminal#138). The drain is fixed at 0.5 s for `targets.toml` targets;
  `sse_drain_timeout` is a constructor argument of the MCP clients for library use.
  Servers that end the stream are unaffected and now reuse the connection.
- **Sovereign mode: a parent issuer must name `admin_personas`**, or `liminal serve` exits
  2, whatever the number of issuers; parent policy rows no longer grant data-plane access
  (tenishai/liminal#83).
- **A Docker build needs techne from somewhere:** pass `--build-context techne=../techne`
  or `--build-arg EXTRA_INDEX_URL=...`; with neither, the build stops and says so
  (tenishai/liminal#117).
- **A persona with no secrets provisioned for a handler now costs one Cabal round trip per
  call to it** in scale mode, because an empty credentials answer is no longer cached
  (tenishai/liminal#140).
- **Smaller visible changes:** `str(MCPTransportError)` no longer starts with
  `transport error:` (tenishai/liminal#112), and `ToolResult.failure` serialises its
  message as a text content block (tenishai/liminal#70).

### Added

- **Operator-only tools.** A capability card's tool entry can set `requires_operator: true`.
  liminal enforces it at `tools/call` and filters it from `tools/list` in every mode:
  single-cabal needs `operator` in the token scope, sovereign needs it in the policy grant
  (`admin:*` satisfies it), and auth-off refuses it (tenishai/liminal#122).
- **`http` targets accept a static `headers` table in `targets.toml`** (tenishai/liminal#135, closes tenishai/liminal#130),
  for example `X-MCP-Readonly = "true"` for GitHub's hosted MCP server. The headers go on
  `initialize`, `tools/list` and `tools/call`. Config load refuses `Authorization`,
  `Mcp-Session-Id`, `Accept`, `Content-Type` and liminal's identity headers
  (`X-Liminal-Persona`, `X-Liminal-Issuer`, `X-Correlation-Id`) in any case, and refuses
  `headers` on a `stdio` target.
- **The MCP client reads Streamable-HTTP SSE responses** (tenishai/liminal#131, closes tenishai/liminal#129). Both
  clients send `Accept: application/json, text/event-stream` on every POST and, when a
  server answers with `text/event-stream`, return the JSON-RPC message whose `id` matches
  the request, stopping there rather than waiting for the stream to close. Plain JSON
  servers are unaffected. This lets GitHub's hosted MCP server
  (`https://api.githubcopilot.com/mcp`) be federated as an `http` target; it always
  streams and rejects a JSON-only Accept with 400.
- **`use_session=True` on either client keeps the server's `Mcp-Session-Id`** from
  `initialize` and sends it on later requests (tenishai/liminal#131, closes tenishai/liminal#129). It is off by
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
  Declaring `tool_scopes` without a target-level `required_scope` denies any tool not
  named; with one, an unnamed tool falls back to it. Per-tool scopes are enforced in
  sovereign mode (tenishai/liminal#81).
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

- **Documentation checked against the code for 0.3.0:** README, SECURITY.md, AGENTS.md,
  CONTRIBUTING.md, docs/design.md, docs/writing-a-handler.md, the proposals and the
  architecture cards (tenishai/liminal#113, tenishai/liminal#146, tenishai/liminal#147,
  tenishai/liminal#151).
- **techne 0.18.0 everywhere liminal gets it** (tenishai/liminal#133). The Dockerfile
  installs `TECHNE_VERSION` and checks the wheel against `TECHNE_WHEEL_SHA256` when
  building from an index, and checks a sibling checkout's version;
  `requirements-sources.txt` pins `v0.18.0` and the `memory` extra floors at
  `techne>=0.18.0`; `tests/test_techne_pin.py` keeps the three in step.
- **A tool-level failure now reaches the agent as text.** `ToolResult.failure(msg)` used to
  serialise as `{"content": [], "isError": true}`; the message is now a text content block
  (tenishai/liminal#70).
- **Parent policy rows no longer answer on the data plane.** Admin standing moves to a
  dedicated lookup used only by the admin gate. Parent rows seed per persona, defaulting to
  `*` as before. A parent issuer that names no `admin_personas` is refused at startup with
  exit 2, whatever the number of issuers (tenishai/liminal#83).
- **`initialize` is authenticated** like every other call to an upstream except `ping`. An
  empty token still sends no header (tenishai/liminal#84).
- **Transport errors carry the cause once.** The client message is now
  `<httpx class>: <cause>`, so agents no longer see "transport error:" twice. `str(exc)` on
  `MCPTransportError` no longer starts with `transport error:` (tenishai/liminal#112).
- **The distribution is named `tenishai-liminal`** (was `liminal`). The bare names are
  taken or open to squatting on PyPI. The import package (`liminal`) and the CLI command
  (`liminal`) are unchanged. `liminal.__version__` now reads the new distribution's
  metadata, and a pin such as `liminal>=0.2` becomes `tenishai-liminal>=0.3`
  (tenishai/liminal#118). An existing editable install keeps the old `liminal`
  distribution beside the new one; run `pip uninstall liminal` and reinstall.
- **The techne floor and source pin move to 0.17.0** (tenishai/liminal#96), and then to
  0.18.0 (tenishai/liminal#133).
- **The Docker image builds from a sibling techne checkout or a package index.** Pass
  `--build-context techne=../techne` or `--build-arg EXTRA_INDEX_URL=...`; with neither,
  the build stops and says which (tenishai/liminal#117).
- **`relevance_signals` is removed from `CapabilityCard`, the built-in handler cards and
  `TargetSpec`** (tenishai/liminal#136, closes tenishai/liminal#116). Nothing read it; it was plumbed for a routing layer
  that does not exist. A `[[target]]` table that still sets it now fails with an unknown-key
  error. Cards from other handler packages that still declare it keep validating, since
  `CapabilityCard` allows extra fields, and the value is ignored.

### Fixed

- **`liminal serve` exits 2 with a message when the trust registry names no parent issuer
  or several**, rather than crashing with a traceback; the `--trust-registry`, `--jwks-url`,
  `--cred-cache-ttl` and `--targets` help text is corrected, and the no-verifier warning
  is no longer printed under `LIMINAL_AUTH_DISABLED=1` (tenishai/liminal#145, closes
  tenishai/liminal#144).
- **Library mode passes a `ToolResult.failure` message through to the caller**, building
  the result content with `to_spec_result_content` (tenishai/liminal#121, closes
  tenishai/liminal#114).
- **The credential resolver no longer caches an empty answer** (tenishai/liminal#140,
  closes tenishai/liminal#139). A 200 whose `credentials` is empty, null or missing is
  returned uncached, so a secret added later is seen on the next call; a body that is not
  a JSON object now returns `{}` as a wrong-shape answer instead of raising
  `AttributeError`. The cost: the route asks the resolver on every dispatch, so a
  persona with no secrets provisioned for a handler now makes one round trip to Cabal per
  call to it, where it made one per cache TTL (15 minutes by default) before.
- **The MCP client reuses its connection after an SSE reply** (tenishai/liminal#138, closes tenishai/liminal#132). Both
  clients stopped reading at the reply, before the chunked terminator, so an
  SSE-answered call almost never reused a connection: 13 requests on one client opened 12
  connections against a local SSE server. They now drain the rest of the
  stream for up to `sse_drain_timeout` seconds (default 0.5) and close the connection if
  the server holds the stream open longer. Plain JSON replies are unchanged.
- **A JSON reply that is not an object is a clean `MCPTransportError`** in both clients,
  instead of an `AttributeError` on `.get` (tenishai/liminal#131, closes tenishai/liminal#129).
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

- **Credentials are resolved only for the parent issuer's callers, and cached per
  issuer.** A persona name is unique only within its issuer, so a foreign cabal's persona
  that shares a name with a home persona could receive the home persona's credentials for
  any handler its grant reached. In sovereign mode the route now calls the resolver only
  when the caller's issuer is in the policy store's `parents()`; the cache is keyed
  `(issuer, persona, handler)` (tenishai/liminal#148, closes tenishai/liminal#143).
- **`notify` no longer returns the webhook URL to the caller.** The URL is a credential
  (Slack-style webhooks carry their secret in the path); the success result, the
  unparseable-URL error and transport errors no longer contain it (tenishai/liminal#150,
  closes tenishai/liminal#149).
- **`files.write` refuses more code-execution and agent-instruction paths:** the
  code-execution paths (all of `.git`, a `.git` pointer file, `.mcp.json` and `.claude.json`), and the
  instruction files `.cursor/`, `.windsurfrules`, `.clinerules` and
  `.github/copilot-instructions.md`, with the same case-insensitive match and the same
  `files:protected_writes` grant as the instruction-file gate (tenishai/liminal#120, part of
  tenishai/liminal#110).
- **Demoting the parent issuer in the trust registry left it a parent.** Its parent rows
  survived, so its personas still passed the admin gate. `liminal serve` now refuses to
  start (exit 2) when the policy DB holds parent rows for an issuer the registry no longer
  names as parent (tenishai/liminal#134, closes tenishai/liminal#87).
- **The sync `MCPClient` now coerces an upstream error `code` like the async client**
  (tenishai/liminal#131, closes tenishai/liminal#129). It never received tenishai/liminal#82's guard, so a hostile
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
  still does (tenishai/liminal#125, closes tenishai/liminal#124).

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
