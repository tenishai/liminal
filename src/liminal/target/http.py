"""``HttpTarget`` — a Streamable-HTTP MCP upstream as a Target.

Generalizes the retired ``MCPProxyHandler``: it fetches + inspects the
upstream's tool catalog at ingest, and forwards calls with **per-call**
identity. It folds in three things the old proxy lacked or did unsafely:

  - **#16 catalog inspection** — an ``UNTRUSTED`` target's catalog is passed
    through ``inspect_catalog`` at ingest (the single chokepoint) before the
    tools ever reach a persona's context.
  - **#13 per-call identity (no shared mutable token)** — the old proxy
    mutated a *shared* client's token in place per call, a cross-persona
    credential-leak footgun. Here every dispatch builds fresh per-call headers
    (persona / issuer / correlation-id, and a per-call ``Authorization`` for
    service-token auth) and passes them as a local argument. Nothing
    persona-specific is ever stored on the client, so concurrent dispatches
    can't leak each other's tokens.
  - **#27 correlation-id** — carried on ``ctx.extra["correlation_id"]``
    (generated if absent) and forwarded as ``x-correlation-id`` on every call.

Failure modes stay explicit (No Silent Failures): ANY failed catalog fetch
— startup or periodic refresh — sets a ``catalog_status`` the health surface
reports as degraded until a fetch succeeds again, never a silently-empty or
silently-stale tool list (liminal#75); only the log severity differs
(error at startup, warning on a refresh, where the last good catalog keeps
serving); a service-token call whose credential did not resolve is REFUSED
with a failure naming the missing key, never sent upstream unauthenticated
(liminal#80); upstream 4xx/5xx or transport error mid-call →
``ToolResult.failure`` with the cause.

Two deployment notes. The owned HTTP client rejects every cookie (a blocking
cookie policy): upstream ``Set-Cookie`` never persists, so one persona's
upstream session can never ride another persona's call (liminal#76) — an
injected ``http_client`` is the injector's responsibility. And because this
gateway holds credentials for its targets, its pod's egress should be
allowlisted to exactly the declared target addresses (liminal#80).
"""

from __future__ import annotations

import asyncio
import http.cookiejar
import uuid
from typing import Any

import httpx
import structlog

from liminal.client.mcp import (
    AsyncMCPClient,
    MCPError,
    MCPRemoteError,
    ToolCallOutcome,
)
from liminal.protocol import Context, ToolResult, ToolSpec
from liminal.target.base import Target, TrustTier
from liminal.target.config import TargetConfigError, TargetSpec
from liminal.target.inspect import inspect_catalog

log = structlog.get_logger(__name__)

# Per-call header names (config — not magic strings inline).
HEADER_PERSONA = "x-liminal-persona"
HEADER_ISSUER = "x-liminal-issuer"
HEADER_CORRELATION_ID = "x-correlation-id"
CORRELATION_ID_KEY = "correlation_id"


class _MissingCredential(Exception):
    """A service-token dispatch whose credential did not resolve; str() is
    the credential key. Rendered by dispatch() as a refusal (liminal#80)."""


class HttpTarget(Target):
    """One HTTP MCP upstream, namespaced under ``spec.name``."""

    def __init__(
        self,
        spec: TargetSpec,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        if spec.transport != "http":
            raise TargetConfigError(
                f"HttpTarget requires transport='http', got {spec.transport!r} "
                f"for target {spec.name!r}"
            )
        spec.validate()
        self.spec = spec
        self.name = spec.name
        self.trust = TrustTier(spec.trust)

        self._http_client = http_client
        self._owned_http = False
        self._client: AsyncMCPClient | None = None
        self._tools: list[ToolSpec] = []
        self._refresh_task: asyncio.Task[None] | None = None
        self._protocol_version: str | None = None
        # Surfaced by /healthz (liminal#75): "not started" -> "ready" on a
        # successful catalog fetch, or "catalog fetch failed: ..." -- a failed
        # target is visible, never a silently-empty tool list.
        self.catalog_status: str = "not started"

    # ---- Target protocol --------------------------------------------------

    async def list_tools(self) -> list[ToolSpec]:
        # Returns the cached, already-inspected catalog. Empty until startup
        # (or if the upstream was unreachable) — same posture as the old proxy.
        return list(self._tools)

    async def dispatch(
        self, tool: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        if self._client is None:
            return ToolResult.failure(
                f"target {self.name!r} not started (call startup() first)"
            )

        try:
            headers = self._build_call_headers(ctx)
        except _MissingCredential as exc:
            log.warning(
                "http_target.credential_missing",
                target=self.name,
                persona=ctx.identity,
                credential_key=str(exc),
            )
            return ToolResult.failure(
                f"credential {exc} for persona {ctx.identity!r} did not "
                f"resolve; refusing to call {self.name!r} unauthenticated"
            )
        log.debug(
            "http_target.dispatch",
            target=self.name,
            tool=tool,
            persona=ctx.identity,
            correlation_id=headers.get(HEADER_CORRELATION_ID),
        )
        try:
            outcome: ToolCallOutcome = await self._client.call_tool(
                tool, payload, extra_headers=headers
            )
        except MCPRemoteError as exc:
            return ToolResult.failure(
                f"upstream {self.name!r} returned error [{exc.code}]: {exc.message}"
            )
        except MCPError as exc:
            return ToolResult.failure(
                f"upstream {self.name!r} transport error: {exc}"
            )

        return ToolResult(content=list(outcome.content), is_error=outcome.is_error)

    def protocol_version(self) -> str | None:
        return self._protocol_version

    # ---- lifecycle --------------------------------------------------------

    async def startup(self) -> None:
        """Connect, initialize, fetch + inspect the catalog, schedule refresh."""
        if self._http_client is None:
            # The owned client REJECTS every cookie (liminal#76): dispatches
            # for different personas share this one client, and an upstream
            # session cookie set on persona A's authenticated call must never
            # replay on persona B's. Stateless bearer-per-call is the model;
            # a blocking cookie policy makes it structural.
            no_cookies = http.cookiejar.CookieJar(
                policy=http.cookiejar.DefaultCookiePolicy(allowed_domains=[])
            )
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.spec.timeout_seconds),
                cookies=no_cookies,
            )
            self._owned_http = True

        # The base client carries NO persona-specific secret. For bearer auth
        # the static target token rides every base call -- the handshake AND
        # the catalog fetch (initialize authenticates like everything else
        # since liminal#75); for service-token / none the base token stays
        # empty, those base calls go out unauthenticated by design, and the
        # per-call Authorization is built fresh in dispatch (#13).
        if self.spec.auth_method == "bearer" and self.spec.bearer_token:
            base_token = self.spec.bearer_token
        else:
            base_token = ""

        def _base_token_provider() -> str:
            return base_token

        self._client = AsyncMCPClient(
            base_url=self.spec.address,
            token_provider=_base_token_provider,
            http_client=self._http_client,
            client_name=self.spec.client_name,
        )

        await self._refresh_tools_once(initialize=True)

        if self.spec.refresh_tools_interval_seconds > 0:
            self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def shutdown(self) -> None:
        if self._refresh_task is not None:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._refresh_task = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._owned_http and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None
            self._owned_http = False

    # ---- internals --------------------------------------------------------

    def _build_call_headers(self, ctx: Context) -> dict[str, str]:
        """Build fresh per-call headers. NEVER stored on the client (#13)."""
        headers: dict[str, str] = {}

        # #13 identity forwarding — the caller's persona/issuer as headers so
        # the backend can self-resolve its own creds from that identity.
        if self.spec.identity == "forward":
            headers[HEADER_PERSONA] = ctx.identity
            headers[HEADER_ISSUER] = ctx.issuer

        # service-token auth — resolve the per-call credential into a per-call
        # Authorization header. Not present on the shared client, so persona
        # A's token can never ride persona B's concurrent request. A missing
        # or empty credential is a REFUSAL, raised for dispatch() to render
        # (liminal#80) -- never an unauthenticated upstream attempt.
        if self.spec.auth_method == "service-token":
            key = self.spec.credential_key or ""
            # STRIP BEFORE TESTING. `if not token` catches "" and None but
            # not "   " — and a trailing newline is the shape a secret read
            # from a file arrives in. Driven: dialed=1, is_error=False,
            # auth='Bearer    ' (Prudence, liminal#84 r1). A whitespace-only
            # credential is a missing credential, and #80's guarantee is that
            # a missing credential is a refusal rather than an anonymous call.
            token = (ctx.credentials.get(key) or "").strip() if key else ""
            if not token:
                raise _MissingCredential(key or "(no credential_key configured)")
            headers["Authorization"] = f"Bearer {token}"

        # #27 correlation-id — carry an inbound one or generate, persist on the
        # context, and forward on every call for end-to-end traceability.
        correlation_id = ctx.extra.get(CORRELATION_ID_KEY)
        if not correlation_id:
            correlation_id = str(uuid.uuid4())
            ctx.extra[CORRELATION_ID_KEY] = correlation_id
        headers[HEADER_CORRELATION_ID] = str(correlation_id)

        return headers

    async def _refresh_tools_once(self, *, initialize: bool = False) -> None:
        if self._client is None:
            return
        try:
            if initialize:
                init_result = await self._client.initialize()
                self._protocol_version = init_result.get("protocolVersion")
            tools_from_upstream = await self._client.list_tools()
        except Exception as exc:  # noqa: BLE001
            # ANY fetch failure marks the status, deliberately (liminal#75):
            # /healthz reads degraded until a fetch succeeds again. A stale
            # catalog on refresh serves an increasingly wrong tool surface --
            # a health check that stays green through that is the exact
            # failure mode this issue exists to kill. Only the log severity
            # is scoped: startup failure means zero tools (error); a refresh
            # failure keeps serving the last good catalog (warning).
            # COARSE ON THE WIRE, DETAIL IN THE LOG. `exc` embeds the
            # upstream's own response body for a 5xx — MCPTransportError is
            # built as f"server {status}: {resp.text[:200]}" — and routes.py
            # serves catalog_status VERBATIM on /healthz, which has no auth at
            # all. So interpolating it here let an UPSTREAM choose what liminal
            # republishes to unauthenticated callers, which is precisely what
            # `trust = "untrusted"` exists to prevent (Prudence, liminal#84 r1;
            # driven: a 500 upstream and a bare GET /healthz returned 200
            # characters of upstream body in the JSON).
            #
            # The status still discriminates the two cases a health check
            # actually needs, and the log lines below already carry the cause.
            # The "catalog fetch failed" prefix is deliberate: it keeps the
            # existing assertion in test_fail_loud.py green without editing
            # someone else's test, and the parenthetical still discriminates
            # the two cases a health check needs to tell apart.
            self.catalog_status = (
                "catalog fetch failed (startup)" if initialize
                else "catalog fetch failed (refresh)"
            )
            if initialize:
                log.error(
                    "http_target.catalog_failed",
                    target=self.name,
                    error=str(exc),
                )
            else:
                log.warning(
                    "http_target.refresh_failed",
                    target=self.name,
                    error=str(exc),
                )
            return

        raw_specs = [
            ToolSpec(
                name=t.name,
                description=t.description,
                input_schema=t.input_schema or {"type": "object", "properties": {}},
            )
            for t in tools_from_upstream
        ]
        # #16 — inspect the catalog at ingest (the single chokepoint). TRUSTED
        # targets pass through; UNTRUSTED get flag/strip/block per policy.
        self._tools = inspect_catalog(
            raw_specs, self.trust, self.spec.on_untrusted
        )
        self.catalog_status = "ready"
        log.info(
            "http_target.tools_refreshed",
            target=self.name,
            trust=self.trust.value,
            fetched=len(raw_specs),
            after_inspection=len(self._tools),
        )

    async def _refresh_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.spec.refresh_tools_interval_seconds)
                await self._refresh_tools_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("http_target.refresh_loop_exception", target=self.name)


def build_http_targets(
    specs: list[TargetSpec],
    *,
    reserved_names: set[str] | None = None,
) -> list[HttpTarget]:
    """Validate specs + build ``HttpTarget`` s, rejecting name collisions.

    ``reserved_names`` are names already taken (e.g. in-process registry keys);
    a target colliding with one — or with another target in ``specs`` — is a
    loud ``TargetConfigError`` (No Silent Failures).
    """
    from liminal.target.config import TargetConfigError

    reserved = set(reserved_names or ())
    seen: set[str] = set()
    targets: list[HttpTarget] = []
    for spec in specs:
        spec.validate()
        if spec.transport != "http":
            raise TargetConfigError(
                f"build_http_targets: target {spec.name!r} has transport "
                f"{spec.transport!r}; only 'http' is supported in Stage A"
            )
        if spec.name in reserved:
            raise TargetConfigError(
                f"target {spec.name!r} collides with an already-registered "
                "handler/target name"
            )
        if spec.name in seen:
            raise TargetConfigError(
                f"duplicate target name {spec.name!r} in target specs"
            )
        seen.add(spec.name)
        targets.append(HttpTarget(spec))
    return targets
