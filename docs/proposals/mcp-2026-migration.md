# MCP 2026-07-28 Migration — dual-era stateless gateway (#62)

|  |  |
| --- | --- |
| **Status** | **Draft — first pass, not for build.** Refresh when work begins. |
| **Authors** | Richard DiMartino + AI |
| **Created** | 2026-07-25 |
| **Tracks** | [#62](https://github.com/tenishai/liminal/issues/62) |
| **Co-design with** | cabal#109 (keyless federation identity) — auth models overlap |
| **Sources** | [MCP RC blog](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/) · [SEP-2575](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2575) · [SEP-2567](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2567) · spec draft: modelcontextprotocol.io/specification/draft |

> **Freshness note:** this captures the RC as of 2026-07-25 (RC locked 2026-05-21, final publishes 2026-07-28). The spec may shift before/after final. Re-verify every claim against the live spec when picking this up — do not treat this doc as ground truth.

---

## Problem

The MCP `2026-07-28` spec goes **stateless**: it removes the `initialize`/`initialized` handshake (SEP-2575) and the `Mcp-Session-Id` protocol-level session (SEP-2567), a deliberate clean break with **no built-in compatibility layer**. liminal implements the removed handshake on **both** sides:

- **as an MCP server** — `src/liminal/server/routes.py` handles `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`; `PUBLIC_METHODS = {initialize, ping, notifications/initialized}` exempts `initialize`/`ping` from bearer auth.
- **as an MCP client to upstreams** — `src/liminal/target/http.py` calls `self._client.initialize()` and reads `protocolVersion`.

Both assume the handshake that is going away.

**liminal's current starting point:** it is pinned to `protocolVersion 2025-06-18` (`DEFAULT_PROTOCOL_VERSION` in `src/liminal/client/mcp.py`, the `protocolVersion` default in `src/liminal/server/mcp_types.py`). The current *stable* spec is already **`2025-11-25`** — so liminal is **one stable revision behind today**, before the `2026-07-28` RC even lands.

The "**not urgent**" claim is therefore *contingent, not automatic*: MCP is version-negotiated, so old↔old keeps working **only while new clients keep negotiating down to `2025-06-18`**. Once clients floor their negotiation at `2025-11-25` (and, later, `2026-07-28`), the break arrives independent of anything in this proposal. Two practical consequences: (a) there is a **nearer-term, smaller task** — bring liminal current to `2025-11-25` — that is worth doing regardless of the stateless port; (b) the stateless port itself remains a deliberate, multi-session effort, but the runway is shorter than "new spec ships Monday" suggests, because liminal is already behind.

## The decision: build a *dual-era bridge*, not just "go stateless"

The spec itself blesses a **dual-era** server that implements *both* the stateless `_meta` model *and* legacy `initialize`, selecting behaviour per-request (compatibility matrix, `/basic/versioning`). A gateway **must** run both eras concurrently to serve mixed clients and upstreams.

Because many good upstream MCP servers are unmaintained and will never port, **a gateway that bridges new stateless clients to old stateful upstreams is exactly what the ecosystem needs.** For liminal this is an opportunity, not merely compliance: the port should make liminal *more* valuable by making it the compatibility seam, not just spec-current.

**Goal:** liminal speaks modern-stateless to new clients, and speaks *both* eras on the client side (modern to new upstreams, legacy `initialize` to old ones), selecting per-target/per-request.

**Non-goals:** dropping legacy support (the whole value is serving both eras); rewriting liminal's per-persona credential model (auth *alignment*, not replacement).

## Port surface

### 1. Server side — `src/liminal/server/routes.py`
- Implement the new **`server/discover`** method (servers MUST) → `{supportedVersions, capabilities, serverInfo, instructions, ttlMs, cacheScope}`.
- Read **`_meta` per request**: `io.modelcontextprotocol/protocolVersion`, `clientInfo`, `clientCapabilities`.
- Streamable HTTP: validate the **`MCP-Protocol-Version` header** mirrors `_meta` protocolVersion → `400` + `HeaderMismatch` (-32020) on mismatch.
- **Retire the `initialize`/`ping` auth exemption.** New rule: *"Authorization MUST be included in every HTTP request."* Unauthenticated discovery moves to the OAuth `401`→`WWW-Authenticate`→PRM `.well-known` static-metadata flow, not a JSON-RPC method carve-out.
- Keep a **legacy `initialize` path** for old clients (dual-era).

### 2. Client side — `src/liminal/target/http.py`
- **Dual-era probing:** try `server/discover` first; fall back to `initialize` on a non-modern error. On HTTP, attempt a modern request and inspect the `400` body for a recognized modern error (`UnsupportedProtocolVersionError`, -32022, lists `supported` versions) before falling back.
- Run **both eras concurrently** — per-target era selection so one gateway fronts legacy and modern upstreams simultaneously.

### 3. Auth — the big lift (`src/liminal/server/` auth path)
- Align with the new authorization model: **RFC 9728** Protected Resource Metadata + **RFC 8707** resource-indicator binding; **`iss` (RFC 9207)** validation; DCR deprecated → **Client ID Metadata Documents**; explicit scope step-up/accumulation.
- liminal today: bearer / JWT (RS256, `aud` + `cabal_scope`). This aligns *onto* the OAuth PRM story rather than replacing the per-persona model.
- **Co-design with cabal#109** (keyless verifiable-credential federation identity) — both are "establish cross-boundary trust without a pre-shared relationship," and doing them together avoids two divergent trust rewrites.

### Lower-impact — verify, don't assume
- **MRTR** (SEP-2322) replaces server-initiated `roots`/`sampling`/`elicitation`. liminal likely does not rely on these (cf techne#463 — sampling was a dead end); **confirm** before assuming zero work.
- **`Mcp-Session-Id`:** the server issues one only under auth-off (#192), for the scratchpad's per-client buckets; with auth on it issues none. The outbound client (`src/liminal/client/mcp.py`) can keep one: `SESSION_HEADER` is echoed after `initialize` when the client is built with `use_session=True`, which is off by default; `HttpTarget` sets it only for a target with `session = "per-persona"`, with one client per persona and a separate one for the catalog fetch (liminal#172). `Mcp-Session-Id` is also in `RESERVED_HEADERS` (`src/liminal/target/config.py`), so a target config cannot set it. That opt-in path, the per-persona session store in `HttpTarget`, and the reserved-header entry are what the port has to revisit. Confirm no other per-connection state is pinned.
- **Subscriptions:** list-change notifications now come from a `subscriptions/listen` request with a persistent SSE response. Check whether liminal proxies list-change and adapt.
- **Deprecated (12-month window, not removed):** Roots, Sampling, Logging (SEP-2577); HTTP+SSE transport (SEP-2596). No action required yet.

## Open questions (unspecified in the RC)
- Explicit fate of `notifications/initialized`.
- Whether `server/discover` is auth-exempt (the spec states "every request" must carry auth, with no stated method-level carve-out).
- Concrete guidance for a gateway bridging **more than two** upstream eras simultaneously (only the two-party matrix is shown).

## Rough sequencing / effort (Claude-time)
1. **Read-and-confirm pass** — re-verify the spec at pick-up time; confirm the MRTR/session/subscription assumptions against liminal's real code. **Resolve the open question "is `server/discover` auth-exempt?" first** — it directly contradicts today's `initialize`/`ping` carve-out (`PUBLIC_METHODS`), so its answer gates the whole server-side auth retirement in step 2. Also decide whether to fold in the smaller "get current to `2025-11-25`" bump. *(small)*
2. **Server-side stateless path** — `server/discover` + `_meta` handling + header validation, behind a legacy `initialize` fallback. *(moderate)*
3. **Client-side dual-era probing.** *(moderate)*
4. **Auth alignment** — RFC 9728/8707/9207, co-designed with cabal#109. *(large — dominates)*

Multi-session. Auth is the long pole. Nothing here is on a Monday-morning clock.
