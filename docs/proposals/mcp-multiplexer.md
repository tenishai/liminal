# MCP Multiplexer — typed federated targets (#12)

|  |  |
| --- | --- |
| **Status** | Implemented (`dispatch/multiplexer.py`, `target/http.py`), except the `stdio` transport (Stage B), which is config-validated but refused at startup |
| **Authors** | Richard DiMartino + AI |
| **Created** | 2026-07-02 |
| **Implements** | #12 (flagship, per the #5 standalone re-scope) |
| **Folds in** | #16 (tool-description inspection), #13 (persona-header identity), #27 (correlation-id + per-target protocol version) |
| **Gated by** | phase-0 hardening (merged, #28) — the dispatcher-contract tripwire tests guard this refactor |

---

## Goal

Turn liminal from *in-process-handlers + a bolted-on `MCPProxyHandler`* into a **thin MCP multiplexer over typed targets**. A backend becomes a **named target with a transport** (`in_process` | `http` | `stdio`); in-process handlers become *one target kind* among others; federation is first-class, not an add-on. Target config is modeled on agentgateway's `McpTargetSpec` so liminal can *optionally* compose behind agentgateway later without a rewrite (the #5 "swappability insurance").

## Non-goals (deliberate scope boundaries)

- **No `binds → listeners → routes` Envoy layering** (#12 says skip it; correct at sovereign-personal-fleet scale — pure overhead).
- **No change to the auth / policy / admin layer.** The federation authz (#21 multi-issuer, #22 PolicyStore, `/admin/policy`) sits *above* dispatch on a stable seam and is untouched. This is a dispatch/target-layer refactor only.
- **No full declarative config schema** — #12 defines the target *model* + a minimal config path; the versioned/validated declarative schema is #15, which rides on this model.

---

## The core abstraction: `Target`

A `Target` is a namespace with a transport. All three kinds satisfy one protocol:

```python
class Target(Protocol):
    name: str                 # the namespace / authz key (== registry key today)
    trust: TrustTier          # TRUSTED | UNTRUSTED — gates catalog inspection
    async def startup(self) -> None: ...
    async def shutdown(self) -> None: ...
    async def list_tools(self) -> list[ToolSpec]: ...       # this target's catalog, UNprefixed
    async def dispatch(self, tool: str, payload: dict, ctx: Context) -> ToolResult: ...
    def protocol_version(self) -> str | None: ...           # negotiated MCP version (None for in_process)
```

Three implementations:

| Kind | What it is | Source |
|---|---|---|
| **`InProcessTarget`** | Adapts an existing `Handler` (scratchpad, files, web, notify, memory) — `tools()`→`list_tools()`, `dispatch()` passthrough. Always `TRUSTED`. | Refactor of today's handlers — **no handler code changes** |
| **`HttpTarget`** | Streamable-HTTP MCP upstream. Generalizes `MCPProxyHandler`: fetches + inspects the upstream catalog, forwards calls with per-call persona identity. | Generalize existing proxy |
| **`StdioTarget`** | Spawns a stdio MCP child (identity-agnostic tools only). | **Net-new** (no stdio transport exists today) |

## The multiplexer

`InProcessDispatcher` generalizes into a `Multiplexer` that holds targets by name and **preserves today's public surface verbatim** (this is what keeps the federation authz seam intact — the phase-0 `test_dispatch_contract.py` tests are the tripwire):

- `list_tools()` → each target's catalog, prefixed `"{target.name}.{tool}"` — **same shape, same prefix scheme**.
- `dispatch(*, tool_name, payload, ctx)` → split on `.`, route to the target — **same signature**.
- The authz key stays `tool_name.split(".")[0] == target.name == registry key`. `routes.py`, `_allowed_handlers_for`, the `PolicyStore`, and `create_app`'s authz wiring (`policy_store` / `policy_scope_for` / `policy_tool_extras`) are **unchanged**.

> **Invariant (guarded by phase-0 tests):** registry name == target name == authz key; `{target}.{tool}` prefixing; `dispatch` signature; `grant.allowed_handlers` filters by target name. If a change breaks any, a `test_dispatch_contract.py` test goes red.

## Fold-in #16 — catalog-ingest inspection (acceptance criterion)

`http`/`stdio` targets fetch tool catalogs from **untrusted** upstreams; those descriptions flow into `tools/list` → persona context. The catalog fetch is the **single chokepoint** — inspection lives there, not scattered.

- Each target has a `trust: TrustTier`. `InProcessTarget` is always `TRUSTED`. `http`/`stdio` default `UNTRUSTED` unless the operator marks otherwise.
- At catalog ingest, for `UNTRUSTED` targets, run `inspect_catalog(tools)` → per the target's `on_untrusted` policy (`flag` | `strip` | `block`):
  - **scan** tool name/description/input-schema for injection markers — imperative instructions aimed at the agent, tool-shadowing/override attempts ("ignore previous", "you must"), hidden/zero-width unicode, oversized descriptions.
  - **`flag`**: annotate the tool (prefix description with a trust warning); **`strip`**: drop the description to a neutral stub; **`block`**: drop the tool from the catalog entirely.
- The inspected catalog is cached (respecting `refresh_tools_interval_seconds`). This is **#16's fix, done at the one place it belongs** — and it goes in *with* #12, because the moment federated proxying becomes the core path, this surface is central.

## Fold-in #13 — persona-header identity (kills the token-swap footgun)

Before implementation, `MCPProxyHandler` mutated a **shared** client's token in place per call (`mcp_proxy/handler.py`) — a cross-persona credential-leak footgun (#25). `MCPProxyHandler` is now retired. `HttpTarget` replaces it:

- **Per-call request headers, never shared mutable state.** Each dispatch builds fresh headers: forward the caller's identity as `x-liminal-persona: {ctx.identity}` + `x-liminal-issuer: {ctx.issuer}`, and the backend **self-resolves its own creds** from that identity (the #7 model). Existing `service-token` auth stays (resolve `ctx.credentials[key]` per call) but as a per-call header, not a swapped shared token.
- **Hard constraint (verified in the agentgateway eval):** a **`stdio` target cannot carry per-request identity** — stdio children discard per-request headers. So `StdioTarget` is for **identity-agnostic** backends only. Config validation **rejects** (loud `ValueError`, No Silent Failures) a `stdio` target configured with `service-token`/identity-forwarding.

## Fold-in #27 — correlation-id + per-target protocol version

- Generate a **correlation id** at inbound request (or accept an inbound one), carry it on `Context.extra["correlation_id"]`, and forward it as `x-correlation-id` on every `http` target call — end-to-end traceability across the multiplexer→target hop.
- Record each `http`/`stdio` target's **MCP protocol version** at `initialize` (client pins `2025-06-18`; federated targets may differ) and surface it on the target for negotiation/diagnostics.

## Config model (minimal; #15 extends)

A typed `TargetSpec` union, shaped like agentgateway's `McpTargetSpec` for swappability:

```toml
# in the serve config (sovereign trust-registry file or a targets file)
[[target]]
name = "jira"
transport = "http"                     # http | stdio
address = "https://jira-mcp.internal"
trust = "untrusted"                    # default for http/stdio
on_untrusted = "flag"                  # flag | strip | block
identity = "forward"                   # forward | none  (http only)

[[target]]
name = "pdftools"
transport = "stdio"
command = ["npx", "-y", "@vendor/pdf-mcp"]
trust = "untrusted"
on_untrusted = "strip"
# identity forwarding not allowed for stdio — config error if set
```

In-process handlers keep their **entry-point discovery** unchanged (they become `InProcessTarget`s automatically). #12 ships a minimal loader; #15 adds the versioned/validated schema + the simple-common-case path.

---

## Build plan (staged, to de-risk the core refactor)

**Stage A — the refactor + the two must-haves (the bulk of the value):**
1. Introduce `Target` protocol + `TrustTier` + `TargetSpec`.
2. `InProcessTarget` adapts `Handler` (no handler changes); `Multiplexer` replaces `InProcessDispatcher` behind the *identical* public surface. **All existing tests + `test_dispatch_contract.py` stay green** — this is the safety gate.
3. `HttpTarget` generalizes `MCPProxyHandler`, with **#16 catalog inspection at ingest** and **#13 per-call identity headers** built in (the shared-token footgun dies here). Thread the **correlation-id** (#27).
4. Retire `MCPProxyHandler` (its logic now lives in `HttpTarget`).

**Stage B — `StdioTarget` (net-new, additive):**
5. Spawn/manage a stdio MCP child; identity-agnostic only (config validation enforces). Catalog inspection applies (usually `strip`/`block` for third-party stdio tools).

**Stage C — config + protocol-version polish → hands to #15:**
6. Per-target protocol-version negotiation (#27); the minimal `[[target]]` loader. Full declarative schema + validation is #15.

Stages A→B→C are independently shippable PRs. Stage A is the guarded refactor; B and C are additive.

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| Refactor silently breaks the federation authz seam | The phase-0 `test_dispatch_contract.py` tripwire + keeping `routes.py`/authz/`create_app` wiring **untouched** + adapt-don't-rewrite handlers |
| `HttpTarget` regresses the existing proxy behavior | It's a generalization of tested code; port the `MCPProxyHandler` tests onto `HttpTarget`; keep namespacing/refresh semantics identical |
| stdio child lifecycle (hangs, zombies, startup failure) | Confine to Stage B; startup timeout + fail-closed on spawn error; identity-agnostic constraint limits blast radius |
| Untrusted-catalog inspection is bypassable | Inspection at the single ingest chokepoint (not per-call); default `UNTRUSTED` for http/stdio; block-list is defense-in-depth, not the only guard |

## Test strategy

- **Green the whole existing suite + `test_dispatch_contract.py` at every step of Stage A** — the non-negotiable safety gate.
- `HttpTarget`: identity header forwarded per-call (no shared-token mutation — a concurrency test proving persona A's token never rides persona B's request); catalog inspection `flag`/`strip`/`block` each exercised; correlation-id propagated.
- `StdioTarget`: spawn + catalog + dispatch; config rejects identity-forwarding on stdio.
- Multiplexer: mixed in-process + http + stdio targets, `list_tools` prefixing + `dispatch` routing + `grant.allowed_handlers` filtering identical across kinds.

---

## Sign-off questions

1. **Staging** — A (refactor + http + #16/#13) → B (stdio) → C (config/#15) as three PRs, or one? (Recommend three — Stage A is the risky core; ship it guarded before adding stdio.)
2. **Untrusted default** — `http`/`stdio` targets default to `UNTRUSTED` + `on_untrusted="flag"` (visible but annotated)? Or default `block`/`strip` (stricter, but breaks a new proxy until the operator opts in)?
3. **stdio in scope for the first pass** — include Stage B now, or ship A first (http + in-process, which is everything that exists today) and add stdio when a concrete stdio backend appears?
