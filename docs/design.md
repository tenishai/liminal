# liminal: MCP Gateway

|  |  |
| --- | --- |
| **Status** | ORIGINAL PROPOSAL — the implementation diverged. See README.md. |
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

**liminal** (from Latin *limen*, threshold) is an MCP gateway for agents. One MCP connection per agent, many backend handlers behind it. liminal is its own repository and distribution, and it does not depend on cabal. The dependency runs the other way: cabal declares handlers into liminal's `liminal.handlers` entry-point group, and liminal discovers them when cabal is installed alongside it. Each of cabal, techne and liminal stands alone, and the integrations between them are optional. Every persona agent reaches tools through liminal.

> **Correction (#72).** This proposal originally made liminal a module of the `cabal` Python package, running in-process inside the cabal daemon in solo mode. That did not ship. The "solo / dev mode" passages below describe that unbuilt design; what exists is `liminal serve`, a standalone process in every mode.

Handlers are Python packages registered as entry points (`liminal.handlers` group). liminal discovers them at startup and dispatches calls into them; handler `dispatch()` is an in-process coroutine call. This proposal also described a scale mode where each handler runs in its own subprocess behind **stdio JSON-RPC**. That was not built: see the correction under Handler runtime modes.

Credentials are fetched from **Cabal Core's encrypted secrets table** at handler-spawn (or handler-init) time — keyed by `(identity, handler)` per the secrets schema. liminal injects the full credential set for that `(identity, handler)` pair into the handler's runtime; the capability card's `credential_keys` field is documentation (what the handler expects), not enforcement. No plaintext `.env` files on disk.

liminal handles tool scoping via **capability cards** that handlers ship as part of their A2A AgentCard `metadata`. In v1, all handlers declare `activation: always` — the on-demand activation surface (with `liminal__discover` / `liminal__activate` meta-tools, federated discovery via `.well-known/dtsp` with operator approval) is deferred to v2, when handler count justifies the context-window optimization. Cards still declare metadata in v1 so the v2 transition is non-breaking.

> **Correction: credential timing and where cards live.** Credentials are not fetched at handler spawn. When `liminal serve` gets `--cabal-url`, `CabalCoreCredentialResolver` (`server/credentials.py`) calls `{cabal_url}/admin/secrets/{persona}/{handler}` during a `tools/call` and caches a non-empty answer per `(issuer, persona, handler)` for `--cred-cache-ttl` seconds (default 900). An empty answer is not cached. In sovereign mode only callers from the policy store's parent issuer reach the fetch (see Credential Flow). Cards are not embedded in an A2A AgentCard either: liminal reads each handler's `capability_card()` at discovery, and nothing in liminal builds an AgentCard.

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
- `capability_card()` — returns the handler's capability card (activation mode, declared tools, declared credential keys, labels). See the Capability cards section below for the schema. All v1 handlers declare `activation: "always"`; on-demand activation is a v2 polish.

The same protocol works in both deployment modes — the difference is *where* the calls land.

### Handler runtime modes

**Solo / dev mode (in-process).** liminal is a module loaded into the same `cabal` daemon as Cabal Core and the agents. `dispatch()` is a Python coroutine call inside the daemon. There are no subprocesses, no IPC, no extra startup latency. A handler exception is caught by liminal's call site and surfaced to the agent as a structured tool-call error. Process boundary is the daemon's; isolation comes from in-process exception handling, not OS-level fork.

> **Correction (#72): the subprocess runtime below was not built.** What exists is the `Target` abstraction: `InProcessTarget` for handlers and `HttpTarget` for federated MCP upstreams (`--targets`), behind one protocol. A `stdio` target is config-validated but refused at startup (`only 'http' is supported in Stage A`, `target/http.py`); the stdio transport is tracked in #12. So per-handler subprocess isolation, the cleanup-on-disconnect invariant, and the crash-loop breaker below are design, not a deployment mode you can run today.

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

**Credentials come from Cabal Core's encrypted `secrets` table.** When liminal needs to spawn (or first-call) a handler for `(identity, handler)`, it asks Cabal Core for the credentials: in solo mode that's a direct function call into Cabal Core's secrets module; in scale mode it's an authenticated HTTPS call to `GET /secrets/<identity>/<handler>` on Cabal Core. Cabal Core decrypts at request time and returns the dict. (As shipped there is no solo-mode function call and no spawn-time fetch: the resolver calls `{cabal_url}/admin/secrets/{persona}/{handler}` per `tools/call`, cached. See the correction under Proposal.)

**Whole credential set per `(identity, handler)`.** liminal passes the full dict that Cabal Core returns into the handler's `Context.credentials` (and into subprocess env vars in scale mode). The capability card's `credential_keys` field is documentation — it tells the operator and the handler author which keys are expected — but it does not enforce. New keys added via `cbl secret` propagate without touching the card. (Solo scale; in-house handlers; the operator owns the trust boundary.)

**Trust boundary.** liminal itself sees every persona's credentials when it fetches them. At solo scale that's no extra surface (liminal is the daemon that already owns everything). At team / company scale, liminal-the-service is a single point of compromise for every persona's secrets it has cached — comparable to the per-host-secrets-mount tradeoff the prior `.env` model also carried. Mitigations: limit cache TTL (15-minute default; re-fetch on next handler call); never persist fetched credentials to disk; use mTLS between liminal and Cabal Core in scale mode (not built: the resolver authenticates with a bearer token only).

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

> **Not built as shown.** liminal reads none of these three environment variables, has no mTLS client, and mounts no identity directory. The shipped knobs are `liminal serve` flags: `--cabal-url` (Cabal Core base URL; wires the credential resolver), `--cabal-token-env` (name of the env var holding the bearer token liminal presents to Cabal Core, default `LIMINAL_CABAL_TOKEN`) and `--cred-cache-ttl` (seconds, default 900).

Identity directories (`./identities/<persona>/`) are git-managed, mounted read-only, and carry only the non-secret config (`identity.toml`, prompts, hook bindings). **Secrets do not live in this directory**; they live in Cabal Core's encrypted `secrets` table and, as built, are fetched per `tools/call` (see the Credential Flow note).

Agents address liminal as `http://liminal:9100` on the network; 9100 is the `liminal serve --port` default, and liminal serves plain HTTP (no TLS or mTLS listener). Each tool call carries the agent's A2A JWT (`sub=agent_name, cabal_persona=<persona>`). liminal validates the JWT against the JWKS at `--jwks-url` (cabal serves its keys at `/.well-known/jwks.json`), cached with a re-fetch on an unknown `kid`. It reads the persona from `cabal_persona`, falling back to `persona`, and the agent from `sub`; a token missing either is refused. It then dispatches to the handler in-process.

**Standalone, auth off (local)** — `LIMINAL_AUTH_DISABLED=1 liminal serve`, bound to `127.0.0.1` (the `--host` default). This is the README quickstart: one gateway on a workstation serving an agent on the same host, with no Cabal Core. Its security model differs from both modes above, so state it rather than let someone discover it:

- **The bind address is the only boundary.** There is no JWT and no persona. Anything that can reach the port can call every tool, so never bind it to a non-loopback address.
- **Every caller is the same caller.** Claims are synthesised with `identity = agent_name = "anonymous"`, so handlers that scope by persona or agent collapse to one shared scope. `scratchpad`, keyed by `(identity, agent_name)`, becomes one bucket for every client.
- **No per-persona allowlists.** The synthesised claims carry no `cabal_tool_extras`, so `ctx.extra` holds no handler config; its only possible key is `correlation_id`, copied from a caller's `x-correlation-id` header. With no `files.allowed_paths` claim, the `files` handler uses `LIMINAL_FILES_ALLOWED_PATHS` as the allowlist itself (#68), and with that unset it still refuses everything.
- **No scope gate, but operator-only tools stay refused.** The per-tool scope gate needs a sovereign grant, so it does not run here. Tools a card marks `requires_operator` are refused, since no caller can prove operator scope, and `tools/list` hides them. Every other registered tool is listed.

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

As shipped, step 4 runs only when `liminal serve` is given `--cabal-url`: `GET {cabal_url}/admin/secrets/{persona}/{handler}` with a bearer token during the `tools/call`, with non-empty answers cached for the TTL per `(issuer, persona, handler)` (the issuer is empty outside sovereign mode). Without `--cabal-url` no resolver is wired and handlers get empty credentials. In sovereign mode (a policy grant authorized the call) the fetch runs only when the caller's issuer is one of the policy store's `parents()`; a caller from any other issuer gets empty credentials and liminal logs `credential.skipped_non_parent_issuer`, because the secrets path carries no issuer and a foreign issuer can mint any persona name (#143). There is no direct function call and no mTLS.

**Handler pooling** (the unbuilt subprocess design): keyed by `(persona, handler)`. Two rook-* agents (rook-primus and rook-secundus) share one slack handler runtime — same persona, same credentials. raven's slack runtime is separate. Cross-persona isolation is structural: rook's runtime sees rook's credential dict; raven's runtime sees raven's; liminal never mixes them. What shipped is one handler instance per liminal process, shared by every persona; isolation is per call, through the `ctx.credentials` resolved for that call's caller.

---

## Capability cards: documentation, not enforcement

Each handler ships a capability card that declares its tools, activation mode, and the credential keys it expects. The schema:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `handler` | string | yes | Unique handler identifier (the entry-point key) |
| `description` | string | yes | Human-readable summary of what the handler covers |
| `tools` | object[] | no (default `[]`) | Array of `{name, description}` for each tool the handler provides. An entry may also set `required_scope` (string; overrides the handler-level scope for that tool, even when weaker) and `requires_operator` (bool, default false; refused and hidden from `tools/list` unless the caller holds `operator`). |
| `activation` | enum | no (default `"always"`) | `"always"` (visible in every `list_tools` response) \| `"on_demand"` (v2 — activated when the agent calls `liminal__activate` after a relevance match) |
| `credential_keys` | string[] | recommended | Keys the handler reads from `ctx.credentials`. Documentation for the operator (what to populate via `cbl secret`) and for the handler author (what to expect) — *not* enforced; liminal passes the whole set Cabal Core returns. |
| `labels` | object | no | Free-form key/value labels (e.g., `tier: "core"`) |
| `required_scope` | string | no | Scope a sovereign grant must hold (or `admin:*`) to call any tool on this handler that has no per-tool `required_scope`. Unset means no scope gate. Applies only in sovereign mode, after the `allowed_handlers` gate. |

The live schema is `CapabilityCard` in `src/liminal/protocol/card.py`.

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
    "credential_keys": ["SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"],
    "labels": {"tier": "core"},
}
```

`credential_keys` tells the **operator** which keys to populate for that handler via `cbl secret set rook slack SLACK_BOT_TOKEN=...` and tells the **handler author** what to read from `ctx.credentials`. It does **not** restrict what liminal injects — liminal always passes the full credential set Cabal Core returns for that `(persona, handler)`. This is forward-compatible: adding a new key via `cbl secret` propagates immediately without a card edit. The trade-off is that liminal itself sees all of a persona's secrets per handler; the trust boundary discussion is above under Handler runtime modes → Trust boundary.

**Where the card lives at runtime.** The card is embedded in the handler's A2A AgentCard `metadata` field (per A2A v1.0 §4). One card, two consumers: liminal reads it to manage handler visibility and credential setup; A2A bulletin-board callers read it for capability discovery. Same source of truth. (Not built: liminal reads the card from `capability_card()` and builds no AgentCard.)

**Failure posture.** Tool listing fails open (a broken card or transient registry error doesn't black-hole the agent's tool surface; the affected handler just doesn't appear). Security-critical operations (credential resolution, registration, `cbl discovery approve`) fail closed (refuse the operation on error rather than proceed with partial state). Credential resolution as shipped is the exception: `CabalCoreCredentialResolver.fetch` is fail-soft, returning `{}` on a network error, a non-200 status, a non-JSON body or a wrong-shaped body, so the handler runs with empty credentials. Only a resolver that raises fails the call (`credential resolution failed`).

---

## Toolset Configuration

> **Not built.** Nothing in liminal reads `toolset.yaml` or a persona's `identity.toml`. Per-caller handler filtering is the `liminal.allowed_handlers` list in the token's `cabal_tool_extras` (alias `tool_extras`) in single-cabal mode, or the policy grant's `allowed_handlers` in sovereign mode, where the token's list is ignored (`_allowed_handlers_for` in `server/routes.py`). Both `tools/list` and `tools/call` apply it.

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
- **Scoping-ready** — capability cards already declare `activation`; v2 splits handlers into `always` / `on_demand` for context-window savings without breaking the v1 card format

---

## Tool Scoping

Tool scoping is the mechanism by which liminal decides which tools an agent sees at any given moment. v1 keeps it simple; v2 adds an on-demand activation surface.

**v1:**

- **Capability cards** ship with every handler (schema and example above). All v1 handlers declare `activation: "always"` — every tool the handler provides shows up in every `list_tools` response that the caller's authorization allows. `tools/list` applies the same handler allowlist and per-tool scope gate as `tools/call`, so a persona never sees a tool it cannot call (#61).
- **Fail-open invariant** for tool listing: a broken capability card or transient registry error doesn't black-hole the agent's tool surface; the missing handler simply doesn't appear, and other handlers stay reachable. Security-critical operations (credential resolution, registration, `cbl discovery approve`) fail-closed. (As shipped, credential resolution is fail-soft unless the resolver raises; see Failure posture above.)
- **QUARANTINED handlers** (not built: there is no crash-loop breaker or quarantine state, see the #72 correction under Handler runtime modes) stay visible in `list_tools` but each `dispatch()` returns a structured `{error: "handler quarantined", retry_after: <seconds>}`. Fail-open on visibility, fail-fast on call — see Handler runtime modes above.

**v2:**

- **On-demand activation** — handlers can declare `activation: "on_demand"`. liminal exposes `liminal__discover` (agent calls with a relevance query; liminal returns matching handlers) and `liminal__activate` (agent activates a matched handler so its tools appear in `list_tools`). Pull-based by design — liminal does not push activations proactively; that's a candidate v3 direction once measurement justifies a particular shape.
- **Federated discovery** via `.well-known/dtsp` — operator-approved. Cards from external URLs become *candidates* surfaced by `cbl discovery list`; the operator runs `cbl discovery approve <handler-id>` to register them. Never silent registration. (The `.well-known/dtsp` URL is kept as the convention name even though the standalone DTSP spec doc was retired into this section.)

---

## Planned Handlers (v1 Cabal scope)

All v1 handlers ship as `activation: always`. On-demand is a v2 polish (see Tool Scoping → v2 above).

| Handler | Notes |
|---------|-------|
| memory | Local techne queries. No credentials required. A caller's `memory.db_path` (in `ctx.extra`) is used if it resolves inside an allowed directory (by default the directory of `LIMINAL_MEMORY_DB`) and refused if it does not; a caller with no override uses `LIMINAL_MEMORY_DB`; with that unset every call is refused. The rules live in `_resolve_db_path`, `MemoryConfig` and `get_handler()` in `handlers/memory.py`. |
| files | Scoped file I/O. The allowlist is `files.allowed_paths` in `ctx.extra`, supplied by the token's `tool_extras` (single-cabal) or the trust registry's `[tool_extras]` (sovereign). `LIMINAL_FILES_ALLOWED_PATHS` is the allowlist for a caller with no such key; for a caller with one it is a ceiling the key can only narrow, and when it is unset the key is the allowlist; an empty or malformed key grants nothing. Reads and writes outside the allowlist return a structured error. Path traversal (`..`) is rejected before the allowlist check. Writes to protected paths (agent instruction files such as `CLAUDE.md` and `AGENTS.md`, code-execution paths such as `.mcp.json`, `.git/` and `.claude/`, hard-linked targets, and `LIMINAL_FILES_PROTECTED_PATTERNS`) are refused unless the sovereign grant holds `files:protected_writes` (#108, #110, #137). |
| slack | Slack bot operations under the persona's Slack identity. Credentials: `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` per persona. |
| github | GitHub API (PRs, commits, search) under the persona's PAT. Credentials: `GITHUB_TOKEN` per persona. |
| scratchpad | Per-agent ephemeral notes. No external credentials. |
| patterns | Architect's pattern corpus surface, shipped by cabal as `cabal.handlers.patterns` (registered in cabal's `pyproject.toml`). Tools: `patterns.search` and `patterns.record` (`record` is operator-only). It calls techne's `techne.core.patterns` functions in-process against an `architect.db` file located by `patterns.db_path` in `ctx.extra`, falling back to `CABAL_ARCHITECT_DB`; with techne not installed every call fails with a structured error. No credentials. (This proposal described it as a thin MCP proxy to the Architect persona's backend, forwarding the caller's JWT.) |
| datadog | Metrics queries. Credentials: `DATADOG_API_KEY`, `DATADOG_APP_KEY` per persona (typically only on personas that operate infra). |
| atlassian | Jira / Confluence. Credentials per persona. |
| web | HTTP fetch: `web.fetch` and `web.head`. **URL policy: allowlist by hostname** in `ctx.extra["web.allowed_hosts"]`, supplied by the token's `tool_extras` (single-cabal) or the trust registry's `[tool_extras]` (sovereign). An entry matches the host exactly, any subdomain of it, or `*` for everything. With the key absent or empty the handler uses its default of `["*"]`, and no environment variable narrows that default. Every resolved IP is checked against fixed deny ranges (`PRIVATE_NETWORKS` in `handlers/web.py`): loopback, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `0.0.0.0/8`, `fc00::/7`, link-local, multicast and reserved space, with IPv4 addresses embedded in IPv6 checked too. That is SSRF protection against pivoting through the agent to reach `http://cabal-core:8080`, `http://litellm:4000`, or cloud metadata services. Allowlisting an internal host does not make it reachable, and no config knob opts out. In sovereign mode the handler also needs scope `web:fetch`. |

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
| Credential fetch (solo + scale) — in-process call vs mTLS to Cabal Core, 15-min cache, key rotation handling | 1 day | `cabal_core.secrets.get(persona, handler)` (solo); `GET /secrets/<persona>/<handler>` client (scale). Shipped as `CabalCoreCredentialResolver` against `/admin/secrets/{persona}/{handler}`, bearer token, no mTLS. |
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
config_version = 1          # recommended (absent loads with a warning); any value other than 1 is refused loudly

# Minimal http target — the common case (two keys required)
[[target]]
name    = "jira"
address = "https://jira-mcp.internal"

# Fuller example — bearer-auth, trusted, with untrusted-tool policy
[[target]]
name        = "github"
address     = "https://github-mcp.internal"
auth_method = "bearer"
bearer_token = "ghp_xxxxxxxxxxxxxxxxxxxx"
trust       = "trusted"
on_untrusted = "strip"      # only matters when trust = "untrusted"
identity    = "forward"     # forward caller persona as x-liminal-persona header

# Basic auth with the credential in the environment. Atlassian's hosted MCP
# authenticates service accounts as Basic base64(email:api_token); set
# ATLASSIAN_BASIC="svc@example.com:<api_token>" (readable form, not encoded).
[[target]]
name             = "atlassian"
address          = "https://atlassian-mcp.example.com/v1"   # the upstream's /v1/mcp, minus /mcp
auth_method      = "bearer"
auth_scheme      = "basic"
bearer_token_env = "ATLASSIAN_BASIC"

# Static request headers (http only, liminal#130). GitHub's hosted MCP server
# reads X-MCP-Readonly to restrict itself server-side.
[[target]]
name         = "github-readonly"
address      = "https://api.githubcopilot.com"
auth_method  = "bearer"
bearer_token = "ghp_xxxxxxxxxxxxxxxxxxxx"

[target.headers]
X-MCP-Readonly = "true"

# Stateful upstream (liminal#172): the server returns an Mcp-Session-Id on
# initialize and refuses later requests without it. Each calling persona gets
# its own upstream session, opened with its own credential.
[[target]]
name           = "vendor"
address        = "https://vendor-mcp.example.com"
auth_method    = "service-token"
credential_key = "VENDOR_TOKEN"
session        = "per-persona"

# Scope-gated target, DENY-BY-DEFAULT (liminal#78).
# NOTE there is no target-level `required_scope` here. That is deliberate --
# see the precedence note below; adding one would DISABLE deny-by-default.
#
# The name differs from the bearer-auth `jira` example above ON PURPOSE: target
# names are the authz key and must be unique, so a file carrying both verbatim
# is refused by build_http_targets with `duplicate target name 'jira'`. An
# earlier revision of this doc shipped exactly that and did not load.
[[target]]
name    = "jira-scoped"
address = "https://jira-mcp.internal"

[target.tool_scopes]
"search"       = "jira:read"
"create_issue" = "jira:write"
# A tool named in neither rule -- e.g. one that appears in a later catalog
# refresh -- resolves to an unsatisfiable sentinel and is refused.

# Scope-gated target, NOT deny-by-default: the target-level scope is the
# fallback for every unnamed tool, so a new upstream tool is CALLABLE by any
# grant holding `confluence:use`.
[[target]]
name           = "confluence"
address        = "https://confluence-mcp.internal"
required_scope = "confluence:use"

[target.tool_scopes]
"search" = "confluence:read"
```

### Keys

| Key | Required | Default | Notes |
|-----|----------|---------|-------|
| `name` | yes | — | Namespace / authz key; becomes the `{name}.{tool}` prefix. No `.` allowed. |
| `address` | yes (http) | — | Upstream base URL, **without** `/mcp`: the client appends it, so `https://host/mcp` would post to `/mcp/mcp`. |
| `transport` | no | `"http"` | `"http"` or `"stdio"`. |
| `command` | yes (stdio) | — | argv list for the spawned stdio child. |
| `trust` | no | `"untrusted"` | `"trusted"` or `"untrusted"`. |
| `on_untrusted` | no | `"flag"` | `"flag"`, `"strip"`, or `"block"` — how to handle suspicious tools from untrusted targets. |
| `identity` | no | `"none"` | `"forward"` (http only) sends caller persona as headers. Rejected for stdio. |
| `auth_method` | no | `"none"` | `"bearer"`, `"service-token"`, or `"none"`. |
| `bearer_token` | if bearer, unless `bearer_token_env` | — | Static credential, inline. Sent on every call (`initialize` included), encoded per `auth_scheme`. Mutually exclusive with `bearer_token_env`. |
| `bearer_token_env` | if bearer, unless `bearer_token` | — | Name of an env var holding the static credential, read when the target starts. Keeps the secret out of a reviewed, image-baked config file. Unset or empty fails the target's startup with an error naming the variable. Refused at load unless `auth_method = "bearer"`. |
| `auth_scheme` | no | `"bearer"` | How the credential rides `Authorization`, for `bearer` and `service-token` alike. `"bearer"`: `Bearer <value>`. `"basic"`: the value is `user:secret` and is sent as `Basic base64(user:secret)`; store the readable form, not a pre-encoded one. `"basic"` needs `auth_method` `"bearer"` or `"service-token"`. |
| `credential_key` | if service-token | — | Key to look up from `ctx.credentials` per call. |
| `timeout_seconds` | no | `30.0` | Per-call timeout. |
| `refresh_tools_interval_seconds` | no | `300` | Catalog re-fetch cadence. `0` disables. |
| `client_name` | no | `"liminal-target"` | Advertised in `initialize` handshake. |
| `required_scope` | no | — | Sovereign scope a grant must hold to call ANY tool on this target. |
| `tool_scopes` | no | `{}` | Table of UNprefixed tool name → scope. Overrides `required_scope` per tool. Declaring it makes the target deny-by-default **only when no `required_scope` is set** — see precedence below. |
| `headers` | no | `{}` | Table of static request headers (http only; a `stdio` target with `headers` is refused). Sent on every call to the target: `initialize`, `tools/list` and `tools/call`. Values must be strings with no CR, LF or NUL. Names must be valid HTTP field names (letters, digits and ``!#$%&'*+-.^_`|~``; no spaces, not even surrounding ones), checked at load rather than on the first request (liminal#141). Names are case-insensitive, and the config is refused if two names differ only by case or if one is `Authorization`, `Mcp-Session-Id`, `Accept`, `Content-Type`, `X-Liminal-Persona`, `X-Liminal-Issuer` or `X-Correlation-Id`: liminal owns these: it sets `Accept`, `Content-Type` and the correlation id per call, the identity headers per call when the target's `identity` is `forward`, `Authorization` when the target authenticates, and `Mcp-Session-Id` when the target's `session` is `per-persona`, so a target config must not set any of them. |
| `session` | no | `"none"` | `"none"` or `"per-persona"` (http only). Set `"per-persona"` for a stateful upstream: one that returns an `Mcp-Session-Id` on `initialize` and refuses later requests without it (the symptom is `catalog fetch failed (startup)` with `-32600 Request must be an initialize request if no session ID is provided` in the log). Each calling persona, keyed by verified issuer and identity, gets its own upstream session, opened on its first call with that call's credential and identity headers. The catalog fetch has a separate session no persona call uses, so a session id never rides another persona's call (liminal#76). A 404 on a session (expired, or the upstream restarted) reopens it and retries once. Shutdown ends each session with an HTTP `DELETE`. A target keeps at most 256 persona sessions and drops the least recently used. A credential that changes mid-session (a rotated service token) keeps the old session until the upstream expires it. `"none"` keeps the gateway stateless: no session id is kept or sent. |

### Health and readiness

`GET /healthz` and `GET /readyz` return the same body: `{"status": "ok" | "degraded", "targets": {name: status}}`, where a target's status is `ready` or a fixed description of what failed (`catalog fetch failed (startup)`, `startup failed`, and so on; never upstream text, because neither path is authenticated). `/healthz` always answers 200 and is the liveness probe: restarting liminal doesn't fix a dead upstream. `/readyz` answers 503 while any target is degraded and is the readiness probe (liminal#159).

### Version handling

- `config_version = 1` — accepted.
- `config_version` absent — accepted with a stderr warning recommending it be set.
- `config_version != 1` — loud error, exit 2 (No Silent Failures).

Unknown keys in a `[[target]]` table are also rejected loudly (a typo like `addres` must not silently no-op).

### Why federated scopes live in config, not in the catalog

An in-process handler's scopes come from its `CapabilityCard`, which is safe because
handler code is server-side and already trusted. A federated target's catalog is authored
by the **upstream**, which defaults to `trust = "untrusted"` — so a catalog-derived scope
map would let an upstream declare that its most dangerous tool requires no scope. The two
maps are keyed identically (`<target>` and `<target>.<tool>`) and merge into one resolver;
only the *source of truth* differs.

Deny-by-default is what makes this hold under catalog refresh. A target's tool list is
re-fetched on a background loop, so a tool that did not exist when the operator wrote the
config can appear later.

**Precedence, and the trap in it.** A tool name resolves in this order:

1. an exact `<target>.<tool>` rule from `tool_scopes`;
2. the target-level `required_scope`;
3. the deny sentinel, **only if** the target declares `tool_scopes`;
4. otherwise open.

So step 2 shadows step 3. **Setting `required_scope` alongside `tool_scopes` turns
deny-by-default OFF** — an unnamed tool falls back to the target scope, and any grant
holding it can call a tool that appeared in a refresh. If you want catalog-refresh
protection, declare `tool_scopes` and leave `required_scope` unset.

The refusal for a sentinel-denied tool deliberately does **not** name the sentinel as a
scope to grant. `has_scope` is plain membership and the grant path validates nothing, so an
operator who granted it would silently disable this gate on every strict target,
permanently.

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
- **Error text is framed too.** Since liminal#66 a failed result's reason is appended to
  the content the agent sees, so an error string is an injection surface exactly like a
  result is — and `MCPRemoteError.message` is the upstream's own JSON-RPC error text,
  while `MCPTransportError` embeds `resp.text` for a 5xx. On an untrusted target the
  upstream half goes inside the envelope and `.error` keeps only liminal's own
  description.
- A message liminal produces **without ever touching upstream output** is not framed —
  `"target not started"` is that case, since no request was made. The envelope means "an
  upstream wrote this", and diluting it would make it useless.

Every string in every block is sanitised, at any depth — not only `type: "text"`. Block
*structure* is preserved: keys, nesting and non-string values are untouched. This matters
because `resource` blocks carry their own `text` field and a `json` block is converted to
text by liminal's wire layer one hop later, so a text-only pass left both delivering the
attack the envelope exists to stop.

**Where the defence actually lives**, in descending order of how much it holds — stated
plainly because the in-band envelope is the weakest of the four and it is the most visible:

1. **The operator's grant** — `trust`, `allowed_handlers`, per-tool scoping. The only
   *authority* boundary. Everything below is labelling.
2. **`_meta`** — the only thing a runtime can act on deterministically, and unforgeable
   from upstream: the outbound client reads only `content` and `isError` from an upstream
   result, so an upstream's own `_meta` is discarded before liminal builds its own. An
   upstream cannot mark itself trusted and cannot supply a nonce.
3. **Hidden-unicode stripping** — mechanical sanitisation, not persuasion.
4. **The in-band banner** — a hint whose reliability belongs to the model, not to liminal.
   A model that would obey an injected instruction may equally ignore the banner.

(4) is not decorative, but its value is *delimitation* rather than persuasion: the content
array on the wire is genuinely mixed — liminal's own error description is appended after
the closing marker — so the markers are what separate upstream bytes from liminal's own in
a flattened concatenation. Do not build a control that depends on the model honouring the
banner. Build on `_meta`.

---

## References

- Pattern Toolbox: shipped as cabal's `patterns` handler (`src/cabal/handlers/patterns.py` in the cabal repo), with direct `architect.db` access rather than a proxy

---

*Rook (SRE AI) — 2026-06-07*
