# MCP 2026-07-28 Migration — dual-era stateless gateway (#62)

|  |  |
| --- | --- |
| **Status** | **Draft — first pass, not for build.** Refresh when work begins. |
| **Authors** | Richard DiMartino + Poe (AI) |
| **Created** | 2026-07-25 |
| **Tracks** | [#62](https://github.com/tenishai/limenal/issues/62) |
| **Co-design with** | cabal#109 (keyless federation identity) — auth models overlap |
| **Sources** | [MCP RC blog](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/) · [SEP-2575](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2575) · [SEP-2567](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2567) · spec draft: modelcontextprotocol.io/specification/draft |

> **Freshness note:** this captures the RC as of 2026-07-25 (RC locked 2026-05-21, final publishes 2026-07-28). The spec may shift before/after final. Re-verify every claim against the live spec when picking this up — do not treat this doc as ground truth.

---

## Problem

The MCP `2026-07-28` spec goes **stateless**: it removes the `initialize`/`initialized` handshake (SEP-2575) and the `Mcp-Session-Id` protocol-level session (SEP-2567), a deliberate clean break with **no built-in compatibility layer**. limenal implements the removed handshake on **both** sides:

- **as an MCP server** — `src/limenal/server/routes.py` handles `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`; `PUBLIC_METHODS = {initialize, ping, notifications/initialized}` exempts `initialize`/`ping` from bearer auth.
- **as an MCP client to upstreams** — `src/limenal/target/http.py` calls `self._client.initialize()` and reads `protocolVersion`.

Both assume the handshake that is going away.

This is **not urgent** — MCP is version-negotiated, so old↔old keeps working; the break is new-client↔old-server, widening over months as the ecosystem adopts. But it is load-bearing and worth designing deliberately.

## The decision: build a *dual-era bridge*, not just "go stateless"

The spec itself blesses a **dual-era** server that implements *both* the stateless `_meta` model *and* legacy `initialize`, selecting behaviour per-request (compatibility matrix, `/basic/versioning`). A gateway **must** run both eras concurrently to serve mixed clients and upstreams.

Because many good upstream MCP servers are unmaintained and will never port, **a gateway that bridges new stateless clients to old stateful upstreams is exactly what the ecosystem needs.** For limenal this is an opportunity, not merely compliance: the port should make limenal *more* valuable by making it the compatibility seam, not just spec-current.

**Goal:** limenal speaks modern-stateless to new clients, and speaks *both* eras on the client side (modern to new upstreams, legacy `initialize` to old ones), selecting per-target/per-request.

**Non-goals:** dropping legacy support (the whole value is serving both eras); rewriting limenal's per-persona credential model (auth *alignment*, not replacement).

## Port surface

### 1. Server side — `src/limenal/server/routes.py`
- Implement the new **`server/discover`** method (servers MUST) → `{supportedVersions, capabilities, serverInfo, instructions, ttlMs, cacheScope}`.
- Read **`_meta` per request**: `io.modelcontextprotocol/protocolVersion`, `clientInfo`, `clientCapabilities`.
- Streamable HTTP: validate the **`MCP-Protocol-Version` header** mirrors `_meta` protocolVersion → `400` + `HeaderMismatch` (-32020) on mismatch.
- **Retire the `initialize`/`ping` auth exemption.** New rule: *"Authorization MUST be included in every HTTP request."* Unauthenticated discovery moves to the OAuth `401`→`WWW-Authenticate`→PRM `.well-known` static-metadata flow, not a JSON-RPC method carve-out.
- Keep a **legacy `initialize` path** for old clients (dual-era).

### 2. Client side — `src/limenal/target/http.py`
- **Dual-era probing:** try `server/discover` first; fall back to `initialize` on a non-modern error. On HTTP, attempt a modern request and inspect the `400` body for a recognized modern error (`UnsupportedProtocolVersionError`, -32022, lists `supported` versions) before falling back.
- Run **both eras concurrently** — per-target era selection so one gateway fronts legacy and modern upstreams simultaneously.

### 3. Auth — the big lift (`src/limenal/server/` auth path)
- Align with the new authorization model: **RFC 9728** Protected Resource Metadata + **RFC 8707** resource-indicator binding; **`iss` (RFC 9207)** validation; DCR deprecated → **Client ID Metadata Documents**; explicit scope step-up/accumulation.
- limenal today: bearer / JWT (RS256, `aud` + `cabal_scope`). This aligns *onto* the OAuth PRM story rather than replacing the per-persona model.
- **Co-design with cabal#109** (keyless verifiable-credential federation identity) — both are "establish cross-boundary trust without a pre-shared relationship," and doing them together avoids two divergent trust rewrites.

### Lower-impact — verify, don't assume
- **MRTR** (SEP-2322) replaces server-initiated `roots`/`sampling`/`elicitation`. limenal likely does not rely on these (cf techne#463 — sampling was a dead end); **confirm** before assuming zero work.
- **`Mcp-Session-Id`:** a grep found no session-id use in limenal today — likely little to change. Confirm no per-connection state is pinned.
- **Subscriptions:** list-change notifications now come from a `subscriptions/listen` request with a persistent SSE response. Check whether limenal proxies list-change and adapt.
- **Deprecated (12-month window, not removed):** Roots, Sampling, Logging (SEP-2577); HTTP+SSE transport (SEP-2596). No action required yet.

## Open questions (unspecified in the RC)
- Explicit fate of `notifications/initialized`.
- Whether `server/discover` is auth-exempt (the spec states "every request" must carry auth, with no stated method-level carve-out).
- Concrete guidance for a gateway bridging **more than two** upstream eras simultaneously (only the two-party matrix is shown).

## Rough sequencing / effort (Claude-time)
1. **Read-and-confirm pass** — re-verify the spec at pick-up time; confirm the MRTR/session/subscription assumptions against limenal's real code. *(small)*
2. **Server-side stateless path** — `server/discover` + `_meta` handling + header validation, behind a legacy `initialize` fallback. *(moderate)*
3. **Client-side dual-era probing.** *(moderate)*
4. **Auth alignment** — RFC 9728/8707/9207, co-designed with cabal#109. *(large — dominates)*

Multi-session. Auth is the long pole. Nothing here is on a Monday-morning clock.
