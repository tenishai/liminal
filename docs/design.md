# liminal: MCP Gateway

|  |  |
| --- | --- |
| **Status** | Proposal |
| **Authors** | Rook (SRE AI), Richard DiMartino |
| **Created** | 2026-06-07 |

---

## Problem

Agents need a growing set of MCP tools — memory, Slack, GitHub, Datadog, pattern-toolbox, Atlassian, and more. Each is typically its own MCP server with its own process, auth configuration, and lifecycle management. Stacking them naively means every agent runs 8+ MCP server processes, each opens its own transport, and each dumps its full tool schema into the LLM's context window on every turn.

Three problems compound as the tool surface grows:

1. **Process sprawl.** Each MCP server is a separate process with its own startup, health monitoring, and failure modes. Debugging "which server crashed?" means checking each one individually.

2. **Credential management is per-server and fragile.** Each server resolves its own credentials — env vars, config files, service account keys — with no shared abstraction. Adding a new server means wiring up another set of secrets. For a multi-persona platform like Cabal where rook's Slack token differs from raven's, the per-server pattern doesn't scale cleanly.

3. **No dynamic scoping.** Every registered server's tools load into context on every turn, whether relevant or not. Microsoft Research documented this as "tool-space interference" — adding tools *reduces* overall task performance. RAG-MCP (arXiv:2505.03275) measured tool selection accuracy at 13.62% with large tool sets, tripling to 43.13% with retrieval-based filtering. The more services we add, the worse every agent gets at using any of them.

This is the same problem Unix solved in the 1980s with `inetd`: instead of N daemons each binding their own port and managing their own lifecycle, one supervisor bound the ports and dispatched to the right backend on demand. We need an `inetd` for MCP.

---

## Proposal

**liminal** (from Latin *limen*, threshold) is Cabal's bundled MCP gateway. One MCP connection per agent, many backend handlers behind it. Per Cabal's "single package, two deployment modes" decision, liminal is a module of the `cabal` Python package — in solo / dev mode it runs in-process alongside Cabal Core and the agents; in production / scale mode it runs as its own service container. Every persona agent reaches tools through liminal regardless of mode.

Handlers are Python packages registered as entry points (`liminal.handlers` group). liminal discovers them at startup and dispatches calls into them. In solo mode, handler `dispatch()` is a Python function call. In scale mode, each handler runs in its own subprocess and liminal speaks **stdio JSON-RPC** to it. The handler interface is the same in either case; the runtime decides based on deployment mode.

Credentials are fetched from **Cabal Core's encrypted secrets table** at handler-spawn (or handler-init) time — keyed by `(identity, handler)` per the secrets schema. liminal injects the full credential set for that `(identity, handler)` pair into the handler's runtime; the capability card's `credential_keys` field is documentation (what the handler expects), not enforcement. No plaintext `.env` files on disk.

liminal handles tool scoping via **capability cards** that handlers ship as part of their A2A AgentCard `metadata`. In v1, all handlers declare `activation: always` — the on-demand activation surface (with `liminal__discover` / `liminal__activate` meta-tools, federated discovery via `.well-known/dtsp` with operator approval) is deferred to v2, when handler count justifies the context-window optimization. Cards still declare metadata in v1 so the v2 transition is non-breaking.

---

## Prior Art: Open-Source MCP Aggregators

Evaluated 2026-06-07 to understand the competitive landscape for MCP gateway/aggregator patterns:

| Project | What it does | Where scoping lives | Gap |
|---------|-------------|---------------------|-----|
| **MetaMCP** (2,389★, TS) | Most feature-complete aggregator — PostgreSQL-backed, per-tool enable/disable, middleware chain, workspace profiles | Static per-workspace config | No dynamic per-request scoping. Workspace profile change requires restart. Stale (last push 2026-02-08). |
| **MCPlex** (9★, Rust) | Single-binary gateway with IDF-weighted semantic routing and metatool indirection (3 fixed meta-tools as discovery interface) | LLM-initiated pull via `find_tools` | No orchestrator-driven scoping — LLM must ask. No task-context inference. |
| **mcpmu** (11★, Go) | Namespace profiles with five-tier permission resolution (server global deny non-overridable), hot-reload config, TUI/Web UI | Static per-namespace config | Per-process scoping only. No mid-session scope changes. |
| **wanaku** (118★, Java) | Enterprise MCP router — Quarkus + gRPC + Infinispan + Keycloak. Namespace + label filtering, remote MCP federation | Static namespace + label query | Organizational scoping (namespaces group tools statically), not behavioral scoping (what's visible per-request). JVM/K8s-native. |

Every existing approach places scoping in one of three locations: the MCP server (via spec enhancement proposals), the agent itself (MCP-Zero), or a product-specific gateway (Lunar.dev MCPX). Open-source aggregators add a fourth — static config — but none implement dynamic per-request scoping based on task context. liminal's capability-card-based scoping is the v2 direction for that gap; v1 ships with `activation: always` everywhere and validates the rest of the architecture before the on-demand surface lights up.

---

## Handler Model

### Entry-point registration

Handlers are Python packages that register via the `liminal.handlers` entry-point group:

```toml
# pyproject.toml
[project.entry-points."liminal.handlers"]
patterns = "cabal.handlers.patterns:get_handler"
slack    = "cabal.handlers.slack:get_handler"
github   = "cabal.handlers.github:get_handler"
files    = "cabal.handlers.files:get_handler"
memory   = "cabal.handlers.memory:get_handler"
```

liminal discovers all installed handlers at startup by scanning the entry-point group. No manual registration — install the package, restart liminal, the handler appears.

### Handler protocol

Handlers implement a small Python protocol:

```python
class Handler(Protocol):
    def tools(self) -> list[ToolSpec]: ...
    async def dispatch(self, name: str, payload: dict, ctx: Context) -> ToolResult: ...
    def capability_card(self) -> dict: ...
```

- `tools()` — returns the tool definitions this handler provides.
- `dispatch()` — executes a named tool call with the given payload and context. Async because real-world handlers (Slack, GitHub, web) make network calls; `asyncio.gather` of dispatches is how parallel handler use looks at the call site.
- `capability_card()` — returns the handler's capability card (relevance signals, activation mode, declared tools, declared credential keys, labels). See the Capability cards section below for the schema. All v1 handlers declare `activation: "always"`; on-demand activation is a v2 polish.

The same protocol works in both deployment modes — the difference is *where* the calls land.

### Handler runtime modes

**Solo / dev mode (in-process).** liminal is a module loaded into the same `cabal` daemon as Cabal Core and the agents. `dispatch()` is a Python coroutine call inside the daemon. There are no subprocesses, no IPC, no extra startup latency. A handler exception is caught by liminal's call site and surfaced to the agent as a structured tool-call error. Process boundary is the daemon's; isolation comes from in-process exception handling, not OS-level fork.

**Production / scale mode (subprocess).** liminal runs as its own service container. Each handler runs in its own subprocess, keyed by `(identity, handler)`, spawned on first use. liminal speaks **stdio JSON-RPC** to the subprocess — newline-delimited JSON over the handler's stdin/stdout, modeled on MCP's own subprocess transport. The subprocess inherits credentials via env vars (liminal passes them on spawn; never via argv). Benefits at scale:

- **Isolation** — a crashing handler doesn't take down the gateway or other handlers.
- **Resource containment** — memory-hungry handlers don't compete with the gateway process.
- **Independent restart** — liminal can restart a single handler without disrupting active tool sessions.

**Cleanup on clean disconnect.** When an agent disconnects from liminal gracefully (not a crash), liminal does NOT immediately tear down the subprocesses it spawned for that agent's identity — other agents in the same cohort may still be using them. But when the last consumer of an `(identity, handler)` subprocess goes away, liminal closes the subprocess's stdin and waits up to 5s for clean exit before SIGKILLing. Without this invariant, repeated reconnects accumulate orphan FDs and leak processes over time.

### Crash-loop protection (scale mode)

Borrowed pattern: `mcplex:subprocess-circuit-breaker`. Sliding-window: **5 crashes in 60 seconds** → handler state moves to QUARANTINED. Quarantined handlers fail-fast on all tool calls with a structured error, and a health event is emitted to Cabal's event bus. Without this protection, a buggy handler spawns unbounded respawn tasks — MCPlex issue #16 documented load avg 143 and FD exhaustion from exactly this failure mode. Solo / dev mode skips this entirely (no subprocesses to restart); a handler that raises is just a tool-call error, the daemon stays up.

**Interaction with fail-open scoping.** A QUARANTINED handler's tools stay listed in `list_tools` (fail-open for visibility) but every `dispatch()` against them returns a structured `{error: "handler quarantined", retry_after: <seconds>}` immediately. The agent sees a clear signal rather than a black-holed tool surface; the fail-open invariant covers visibility, not call success.

### Context abstraction

The `Context` object carries identity and resolved credentials into each handler call:

```python
class Context:
    identity: str           # persona name (rook, raven, architect)
    agent_name: str         # specific agent (rook-primus, rook-secundus)
    credentials: dict       # full credential set for this (identity, handler)
```

**Credentials come from Cabal Core's encrypted `secrets` table.** When liminal needs to spawn (or first-call) a handler for `(identity, handler)`, it asks Cabal Core for the credentials: in solo mode that's a direct function call into Cabal Core's secrets module; in scale mode it's an authenticated HTTPS call to `GET /secrets/<identity>/<handler>` on Cabal Core. Cabal Core decrypts at request time and returns the dict.

**Whole credential set per `(identity, handler)`.** liminal passes the full dict that Cabal Core returns into the handler's `Context.credentials` (and into subprocess env vars in scale mode). The capability card's `credential_keys` field is documentation — it tells the operator and the handler author which keys are expected — but it does not enforce. New keys added via `cbl secret` propagate without touching the card. (Solo scale; in-house handlers; the operator owns the trust boundary.)

**Trust boundary.** liminal itself sees every persona's credentials when it fetches them. At solo scale that's no extra surface (liminal is the daemon that already owns everything). At team / company scale, liminal-the-service is a single point of compromise for every persona's secrets it has cached — comparable to the per-host-secrets-mount tradeoff the prior `.env` model also carried. Mitigations: limit cache TTL (15-minute default; re-fetch on next handler call); never persist fetched credentials to disk; use mTLS between liminal and Cabal Core in scale mode.

---

## Deployment in Cabal

**Solo / dev mode** — liminal is loaded as a module of the `cabal` daemon. No separate compose service. Handlers are in-process Python callables. Identity config is mounted into the daemon container; credential fetches are direct function calls into Cabal Core's secrets module (also in-process). One container, one log stream.

**Production / scale mode** — liminal runs as its own service container:

```yaml
liminal:
  image: cabal/liminal:latest
  volumes:
    - ./identities:/var/cabal/identities:ro    # non-secret identity config
  environment:
    CABAL_URL: https://cabal-core:8080         # for secrets fetch + JWKS
    CABAL_CLIENT_CERT: /etc/liminal/client.pem # mTLS to Cabal Core
    LIMINAL_CRED_CACHE_TTL: 900                # 15-minute credential cache
```

Identity directories (`./identities/<persona>/`) are git-managed, mounted read-only, and carry only the non-secret config (`identity.toml`, prompts, hook bindings). **Secrets do not live in this directory**; they live in Cabal Core's encrypted `secrets` table and are fetched at handler-spawn time.

Agents address liminal as `http://liminal:9000` (or `https://` with mTLS) on the network. Each tool call carries the agent's A2A JWT (`sub=agent_name, persona=<persona>`). liminal validates the JWT against Cabal Core's JWKS (`GET /jwks.json`, cached with `kid` rotation), extracts the `persona` claim, and routes to the matching `(persona, handler)` runtime (in-process or subprocess depending on mode).

---

## Credential Flow

```
Agent (rook-primus)
  │
  │  MCP call: slack.send_message(channel, text)
  │  Authorization: Bearer <A2A JWT, sub=rook-primus, persona=rook>
  ▼
liminal
  │  1. Validate JWT against Cabal Core's JWKS → extract persona ("rook")
  │  2. Match tool call to handler prefix ("slack")
  │  3. Look up handler runtime for (rook, slack):
  │       solo  mode → in-process callable, may already be initialized
  │       scale mode → subprocess (spawn if absent)
  │  4. If credentials not cached (or TTL expired):
  │       solo  mode → cabal_core.secrets.get(rook, slack)  ←  direct call
  │       scale mode → GET https://cabal-core/secrets/rook/slack  ←  mTLS
  │     Returns the full {SLACK_BOT_TOKEN, SLACK_APP_TOKEN, ...} dict.
  │  5. Dispatch the tool call with Context{identity=rook, credentials=…}
  ▼
Handler.dispatch(name, payload, ctx)
  │  ctx.identity = "rook"
  │  ctx.agent_name = "rook-primus"
  │  ctx.credentials = {SLACK_BOT_TOKEN: ..., SLACK_APP_TOKEN: ...}
  ▼
Tool result → liminal → agent
```

**Handler pooling**: keyed by `(persona, handler)`. Two rook-* agents (rook-primus and rook-secundus) share one slack handler runtime — same persona, same credentials. raven's slack runtime is separate. Cross-persona isolation is structural: rook's runtime sees rook's credential dict; raven's runtime sees raven's; liminal never mixes them.

---

## Capability cards: documentation, not enforcement

Each handler ships a capability card that declares its tools, activation mode, relevance signals, and the credential keys it expects. The schema:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `handler` | string | yes | Unique handler identifier (the entry-point key) |
| `description` | string | yes | Human-readable summary of what the handler covers |
| `tools` | object[] | yes | Array of `{name, description}` for each tool the handler provides |
| `activation` | enum | yes | `"always"` (visible in every `list_tools` response) \| `"on_demand"` (v2 — activated when the agent calls `liminal__activate` after a relevance match) |
| `relevance_signals` | string[] | recommended | Natural-language descriptions of task contexts where these tools are useful. v1 uses them as documentation; v2's on-demand activation uses them as the matching surface for `liminal__discover` |
| `credential_keys` | string[] | recommended | Keys the handler reads from `ctx.credentials`. Documentation for the operator (what to populate via `cbl secret`) and for the handler author (what to expect) — *not* enforced; liminal passes the whole set Cabal Core returns. |
| `labels` | object | no | Free-form key/value labels (e.g., `tier: "core"`) |

Example for the `slack` handler:

```python
CAPABILITY_CARD = {
    "handler": "slack",
    "description": "Slack bot operations under the persona's Slack identity",
    "tools": [
        {"name": "send_message", "description": "Post to a Slack channel or DM"},
        {"name": "search_messages", "description": "Search the bot's accessible history"},
    ],
    "activation": "always",
    "relevance_signals": [
        "notifying the operator about a long-running task result",
        "fetching context from prior conversations in a channel",
    ],
    "credential_keys": ["SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"],
    "labels": {"tier": "core"},
}
```

`credential_keys` tells the **operator** which keys to populate for that handler via `cbl secret set rook slack SLACK_BOT_TOKEN=...` and tells the **handler author** what to read from `ctx.credentials`. It does **not** restrict what liminal injects — liminal always passes the full credential set Cabal Core returns for that `(persona, handler)`. This is forward-compatible: adding a new key via `cbl secret` propagates immediately without a card edit. The trade-off is that liminal itself sees all of a persona's secrets per handler; the trust boundary discussion is above under Handler runtime modes → Trust boundary.

**Where the card lives at runtime.** The card is embedded in the handler's A2A AgentCard `metadata` field (per A2A v1.0 §4). One card, two consumers: liminal reads it to manage handler visibility and credential setup; A2A bulletin-board callers read it for capability discovery. Same source of truth.

**Failure posture.** Tool listing fails open (a broken card or transient registry error doesn't black-hole the agent's tool surface; the affected handler just doesn't appear). Security-critical operations (credential resolution, registration, `cbl discovery approve`) fail closed (refuse the operation on error rather than proceed with partial state).

---

## Toolset Configuration

A `toolset.yaml` declares which handlers are active for a persona:

```yaml
# toolsets/default.yaml — v1
name: default
handlers:
  always: [memory, slack, github, scratchpad, files, patterns]

# toolsets/minimal.yaml — v1
name: minimal
handlers:
  always: [memory, files]
```

Per-identity overrides go in the persona's `identity.toml` (e.g., `raven` doesn't get `slack`; `architect` doesn't get any operator-action handlers).

**v1 ships all handlers as `activation: always`.** The on-demand activation surface (separating handlers into `always` and `on_demand` sections, plus the `liminal__discover` / `liminal__activate` meta-tools) ships in v2 once handler count justifies the context-window optimization. Capability cards already declare `activation` per handler so the v2 transition is non-breaking — operators just split the list.

---

## What This Enables in Cabal

- **One MCP connection per agent** instead of N — each Cabal persona agent talks to liminal, not to 8+ individual MCP servers
- **Persona-scoped credentials** from a single encrypted store — Cabal Core's secrets table is canonical; rook's tokens are decrypted only when liminal needs them for a rook-handler call, never on disk in plaintext
- **Same handler interface in solo and scale modes** — handlers are Python callables in solo, subprocesses in scale, same `dispatch(name, payload, ctx)` either way
- **Handler pooling** across same-persona agents — rook-primus and rook-secundus share the rook slack runtime (and its rate-limit budget)
- **Singleton-persona data backends reachable through liminal** — Architect's pattern corpus, Archivist's federated memory (v2), Librarian's docs index (v2) all expose MCP-tool surfaces fronted by their own liminal handlers; agents call `pattern_search` (or `memory_lookup`, or `doc_lookup`) like any other tool
- **Scoping-ready** — capability cards already declare `activation` and `relevance_signals`; v2 splits handlers into `always` / `on_demand` for context-window savings without breaking the v1 card format

---

## Tool Scoping

Tool scoping is the mechanism by which liminal decides which tools an agent sees at any given moment. v1 keeps it simple; v2 adds an on-demand activation surface.

**v1:**

- **Capability cards** ship with every handler (schema and example above). All v1 handlers declare `activation: "always"` — every tool the handler provides shows up in every `list_tools` response.
- **Fail-open invariant** for tool listing: a broken capability card or transient registry error doesn't black-hole the agent's tool surface; the missing handler simply doesn't appear, and other handlers stay reachable. Security-critical operations (credential resolution, registration, `cbl discovery approve`) fail-closed.
- **QUARANTINED handlers** stay visible in `list_tools` but each `dispatch()` returns a structured `{error: "handler quarantined", retry_after: <seconds>}`. Fail-open on visibility, fail-fast on call — see Handler runtime modes above.

**v2:**

- **On-demand activation** — handlers can declare `activation: "on_demand"`. liminal exposes `liminal__discover` (agent calls with a relevance query; liminal returns matching handlers) and `liminal__activate` (agent activates a matched handler so its tools appear in `list_tools`). Pull-based by design — liminal does not push activations proactively; that's a candidate v3 direction once measurement justifies a particular shape.
- **Federated discovery** via `.well-known/dtsp` — operator-approved. Cards from external URLs become *candidates* surfaced by `cbl discovery list`; the operator runs `cbl discovery approve <handler-id>` to register them. Never silent registration. (The `.well-known/dtsp` URL is kept as the convention name even though the standalone DTSP spec doc was retired into this section.)

---

## Planned Handlers (v1 Cabal scope)

All v1 handlers ship as `activation: always`. On-demand is a v2 polish (see DTSP Integration above).

| Handler | Notes |
|---------|-------|
| memory | Local techne queries (per-agent SQLite). No credentials required. |
| files | Scoped file I/O. Each persona's `identity.toml` declares a `files.paths` allowlist (e.g., `["~/projects/cabal", "~/.cbl/scratch/rook"]`); reads and writes outside the allowlist return a structured error. Path traversal (`..`) is rejected before the allowlist check. |
| slack | Slack bot operations under the persona's Slack identity. Credentials: `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` per persona. |
| github | GitHub API (PRs, commits, search) under the persona's PAT. Credentials: `GITHUB_TOKEN` per persona. |
| scratchpad | Per-agent ephemeral notes. No external credentials. |
| patterns | Architect's pattern corpus surface (see [`pattern-toolbox.md`](pattern-toolbox.md)). The handler is a thin MCP proxy to the Architect singleton-persona's data backend. No service-specific API key — the agent's A2A JWT is forwarded; Architect authenticates the caller against Cabal Core's JWKS the same way liminal does. |
| datadog | Metrics queries. Credentials: `DATADOG_API_KEY`, `DATADOG_APP_KEY` per persona (typically only on personas that operate infra). |
| atlassian | Jira / Confluence. Credentials per persona. |
| web | Web search + fetch. **URL policy: allowlist by hostname**, declared per persona in `identity.toml` as `web.allowed_hosts = ["*"]` (broad) or specific domains. Default denies `localhost`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, and link-local — explicit SSRF protection against pivoting through the agent to reach `http://cabal-core:8080`, `http://litellm:4000`, or cloud metadata services. Operators who genuinely need internal fetches whitelist hosts explicitly. |

---

## Open Questions

1. **Cohort rate-limit sharing.** Two rook-* agents share one slack handler runtime, which means they share Slack's rate limit budget for the rook bot identity. If rook-primus and rook-secundus are both posting at high frequency, one will throttle the other. Acceptable in v1 because they're conceptually the same actor to the world; revisit if cohort sizes grow.

2. **Handler packaging.** Mono-repo (handlers live in the `cabal` package as `cabal.handlers.*`) vs per-handler repos. Entry-point mechanism supports both. Lean: mono-repo for v1; split a handler out only if it grows its own release cadence or gets independent contributors.

3. **Credential cache invalidation on rotation.** When the operator runs `cbl secret rotate slack rook` to change a token, liminal's 15-minute cache is stale until TTL. Acceptable at solo scale (operator can `cbl liminal flush-creds rook slack` if needed). At scale, Cabal Core could push a cache-bust event over the event bus — defer unless it bites.

4. **Solo-mode shared-process security model.** In solo / dev mode, liminal, all handlers, Cabal Core, and the agents all run in one Python process — there is no OS-level isolation between rook's credentials and raven's at the process level. The structural property is *in-process discipline*: liminal never passes raven's credential dict into a rook-targeted dispatch. A handler that introspects the parent process's memory could see other personas' creds. At solo scale (single-operator, in-house handler code) this is acceptable. At scale (where handlers may be third-party), use scale mode for real OS-level isolation.

---

## Relationship to wanaku

wanaku (evaluated 2026-06-07) is the enterprise/K8s answer to this exact problem. liminal borrows four patterns from it (`heartbeat-liveness`, `forward-ref-federation`, `label-based-batch-ops`, `toolset-repo-catalog`) but stays in Python and in the docker-compose deployment shape rather than adopting Java/Quarkus/Infinispan/K8s.

---

## Effort Estimate

| Work Item | Effort | Deliverable |
|-----------|--------|-------------|
| liminal core (handler loading via entry points; in-process call path; MCP Streamable HTTP server) | 3 days | Python module loadable into `cabal` daemon; MCP server for solo mode |
| Subprocess transport (scale mode) — stdio JSON-RPC framing + spawn/cleanup lifecycle | 1.5 days | Subprocess handler runtime + cleanup-on-disconnect invariant + crash-loop circuit breaker |
| Credential fetch (solo + scale) — in-process call vs mTLS to Cabal Core, 15-min cache, key rotation handling | 1 day | `cabal_core.secrets.get(persona, handler)` (solo); `GET /secrets/<persona>/<handler>` client (scale) |
| Capability cards (v1: `always`-only, declared metadata, no on-demand wiring) | 1 day | Card schema, registry, fail-open invariant for tool listing |
| First v1 handler set (memory, files, slack, github, patterns, scratchpad) | 2 days | Working handlers for rook + raven + architect with the security boundaries spelled out above (files allowlist, web allowlist) |
| **Total** | **~8.5 days** | |

DTSP on-demand activation (`liminal__discover`, `liminal__activate`, federated `.well-known/dtsp` discovery with operator approval) is v2 work — not in this estimate.

---

## Declarative targets (`--targets`) — #15

Federated MCP upstreams are declared in a versioned TOML file and loaded at startup via `liminal serve --targets <path>`.

> **Stage status:** `http` targets are served now. `stdio` targets are **config-validated but not yet served** (Stage B) — declaring one is accepted by the schema but rejected at startup with a clear `error: --targets: …` diagnostic (exit 2). A target `name` that collides with a built-in handler (e.g. `memory`) is likewise rejected loudly at startup. Any bad `--targets` config exits 2, never a traceback.

### Schema

```toml
# targets.toml
config_version = 1          # required; liminal will refuse version != 1 loudly

# Minimal http target — the common case (two keys required)
[[target]]
name    = "jira"
address = "https://jira-mcp.internal/mcp"

# Fuller example — bearer-auth, trusted, with untrusted-tool policy
[[target]]
name        = "github"
address     = "https://github-mcp.internal/mcp"
auth_method = "bearer"
bearer_token = "ghp_xxxxxxxxxxxxxxxxxxxx"
trust       = "trusted"
on_untrusted = "strip"      # only matters when trust = "untrusted"
identity    = "forward"     # forward caller persona as x-liminal-persona header
```

### Keys

| Key | Required | Default | Notes |
|-----|----------|---------|-------|
| `name` | yes | — | Namespace / authz key; becomes the `{name}.{tool}` prefix. No `.` allowed. |
| `address` | yes (http) | — | Upstream MCP endpoint URL. |
| `transport` | no | `"http"` | `"http"` or `"stdio"`. |
| `command` | yes (stdio) | — | argv list for the spawned stdio child. |
| `trust` | no | `"untrusted"` | `"trusted"` or `"untrusted"`. |
| `on_untrusted` | no | `"flag"` | `"flag"`, `"strip"`, or `"block"` — how to handle suspicious tools from untrusted targets. |
| `identity` | no | `"none"` | `"forward"` (http only) sends caller persona as headers. Rejected for stdio. |
| `auth_method` | no | `"none"` | `"bearer"`, `"service-token"`, or `"none"`. |
| `bearer_token` | if bearer | — | Static token sent as `Authorization: Bearer`. |
| `credential_key` | if service-token | — | Key to look up from `ctx.credentials` per call. |
| `timeout_seconds` | no | `30.0` | Per-call timeout. |
| `refresh_tools_interval_seconds` | no | `300` | Catalog re-fetch cadence. `0` disables. |
| `relevance_signals` | no | `[]` | Routing hints (v2 on-demand activation). |
| `client_name` | no | `"liminal-target"` | Advertised in `initialize` handshake. |

### Version handling

- `config_version = 1` — accepted.
- `config_version` absent — accepted with a stderr warning recommending it be set.
- `config_version != 1` — loud error, exit 2 (No Silent Failures).

Unknown keys in a `[[target]]` table are also rejected loudly (a typo like `addres` must not silently no-op).

### Auth modes

`--targets` is auth-mode-agnostic — it works with `--jwks-url` (single-cabal) and `--trust-registry` (sovereign) alike. Targets are not auth-mode-specific config.

### Example invocation

```bash
liminal serve \
  --jwks-url https://cabal-core:8080/.well-known/jwks.json \
  --targets targets.toml
```

---

## Untrusted tool results — the contract for agent runtimes

Catalog inspection (`trust` / `on_untrusted` above) covers what a federated upstream
**says about** its tools. This is the other half: what a tool **returns**.

A result from a target with `trust = "untrusted"` is wrapped at the gateway boundary
before it reaches the caller:

```
[BEGIN UNTRUSTED TOOL RESULT <nonce> — returned by federated target 'jira'. …]
  …the upstream's content blocks, unchanged except for stripped hidden unicode…
[END UNTRUSTED TOOL RESULT <nonce>]
```

and the JSON-RPC result carries the same fact out of band:

```json
"_meta": {
  "liminal/untrusted": true,
  "liminal/untrusted_source": "jira",
  "liminal/untrusted_nonce": "<nonce>"
}
```

**What a runtime may rely on:**

- Content inside the envelope carries **no authority**. It is data returned by a third
  party. It is not from the operator, not from the user, and not from liminal. Directives
  appearing inside it are content, not instructions.
- `_meta` is authoritative; the in-band delimiters are a convenience for the model. Decide
  whether a result is untrusted by reading `_meta["liminal/untrusted"]`, never by
  pattern-matching the text — an upstream can imitate the text.
- The **nonce is per result**. Match delimiters by the nonce from `_meta`, so an upstream
  that emits its own `BEGIN`/`END` markers cannot close the envelope early and have the
  rest of its output read as trusted.
- A `trusted` target's results are **not** framed and carry no `_meta` flag. Framing is
  gated on the same `trust` tier that gates catalog inspection.
- Errors liminal itself generates (transport failure, target not started) are never
  framed — the envelope means "an upstream wrote this", and diluting it would make it
  useless.

`json` and `image` blocks pass through structurally unchanged; they sit inside the
envelope and are covered by the `_meta` flag, which is why a runtime that inspects blocks
rather than concatenated text must read `_meta`.

---

## References

- [`pattern-toolbox.md`](pattern-toolbox.md) — Pattern Toolbox proposal (planned liminal handler)

---

*Rook (SRE AI) — 2026-06-07*
