"""``HttpTarget`` — a Streamable-HTTP MCP upstream as a Target.

Generalizes the retired ``MCPProxyHandler``: it fetches + inspects the
upstream's tool catalog at ingest, and forwards calls with **per-call**
identity. It folds in three things the old proxy lacked or did unsafely:

  - **#79 result framing** — an ``UNTRUSTED`` target's tool RESULTS are
    wrapped in a nonce-tagged envelope at dispatch and flagged in the response
    ``_meta``, so instruction-shaped text an upstream returns is marked as
    data rather than flowing to the agent verbatim.
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

Failure modes stay explicit (No Silent Failures): upstream unreachable →
empty catalog + a clear dispatch failure; upstream 4xx/5xx or transport error
mid-call → ``ToolResult.failure`` with the cause.
"""

from __future__ import annotations

import asyncio
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
from liminal.target.inspect import (
    UnsanitizableResult,
    frame_untrusted_result,
    inspect_catalog,
    new_envelope_nonce,
)

log = structlog.get_logger(__name__)

# Per-call header names (config — not magic strings inline).
HEADER_PERSONA = "x-liminal-persona"
HEADER_ISSUER = "x-liminal-issuer"
HEADER_CORRELATION_ID = "x-correlation-id"
CORRELATION_ID_KEY = "correlation_id"


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

        headers = self._build_call_headers(ctx)
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
            return self._error_result(
                reason=f"upstream {self.name!r} returned error [{exc.code}]",
                upstream_text=exc.message,
            )
        except MCPError as exc:
            # An MCPTransportError message can embed the upstream's response
            # body (`server {status}: {resp.text[:200]}`), so this is not
            # unconditionally our own prose either.
            return self._error_result(
                reason=f"upstream {self.name!r} transport error",
                upstream_text=str(exc),
            )

        content = list(outcome.content)
        if self.trust is TrustTier.UNTRUSTED:
            # #79 — the dispatch-time half of #16. Catalog inspection covers
            # what the upstream SAYS about its tools; this covers what it
            # RETURNS. The nonce goes out-of-band in the response `_meta` so a
            # runtime can verify the delimiters instead of trusting their shape.
            nonce = new_envelope_nonce()
            try:
                framed = frame_untrusted_result(content, self.name, nonce)
            except UnsanitizableResult as exc:
                # Fail closed and, critically, fail as a ToolResult rather than
                # letting an exception escape dispatch(): _handle_tools_call
                # catches only UnknownTool/DispatchError, so anything else
                # becomes an unhandled 500 instead of a JSON-RPC error.
                log.warning(
                    "http_target.result_unsanitizable",
                    target=self.name, tool=tool, error=str(exc),
                )
                return ToolResult.failure(
                    f"refused: {self.name!r} returned content that could not be "
                    f"sanitised ({exc}); it is not forwarded"
                )
            return ToolResult(
                content=framed,
                is_error=outcome.is_error,
                liminal_untrusted=True,
                liminal_untrusted_source=self.name,
                liminal_untrusted_nonce=nonce,
            )
        return ToolResult(content=content, is_error=outcome.is_error)

    def protocol_version(self) -> str | None:
        return self._protocol_version

    # ---- lifecycle --------------------------------------------------------

    async def startup(self) -> None:
        """Connect, initialize, fetch + inspect the catalog, schedule refresh."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.spec.timeout_seconds)
            )
            self._owned_http = True

        # The base client carries NO persona-specific secret. For bearer auth we
        # pin the static token here so the catalog fetch is authenticated; for
        # service-token / none the base token stays empty and the per-call
        # Authorization is built fresh in dispatch (#13).
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

    def _error_result(self, *, reason: str, upstream_text: str) -> ToolResult:
        """A failed dispatch whose message may carry upstream-authored bytes.

        Since liminal#66 a ToolResult's ``.error`` is appended to the content
        the agent sees, so an error string is now an injection surface exactly
        like a successful result is. Both upstream error paths can embed
        upstream output — ``MCPRemoteError.message`` is the upstream's own
        JSON-RPC error text, and ``MCPTransportError`` embeds ``resp.text`` for
        a 5xx — so on an UNTRUSTED target the upstream half goes inside the
        envelope and ``.error`` keeps only liminal's own description.

        The result stays legible per #66: the agent still gets a reason, and
        still gets the upstream's text — framed rather than dropped.
        """
        if self.trust is not TrustTier.UNTRUSTED:
            return ToolResult.failure(f"{reason}: {upstream_text}")
        nonce = new_envelope_nonce()
        # GUARDED LIKE THE SUCCESS PATH. This call was unguarded, so an upstream
        # error message — MCPRemoteError.message is unvalidated — bypassed the
        # depth bound the success path enforces. The Multiplexer's blanket
        # except contains it, so this was a message-parity gap rather than a
        # crash: the caller got "raised UnsanitizableResult" instead of the
        # refusal prose. (Prudence, liminal#82 round 3, nit 3.)
        try:
            framed = frame_untrusted_result(
                [{"type": "text", "text": upstream_text}], self.name, nonce
            )
        except UnsanitizableResult as exc:
            return ToolResult.failure(
                f"{reason}, and the upstream's error text could not be "
                f"sanitised ({exc}); it is not forwarded"
            )
        return ToolResult(
            content=framed,
            is_error=True,
            error=reason,
            liminal_untrusted=True,
            liminal_untrusted_source=self.name,
            liminal_untrusted_nonce=nonce,
        )

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
        # A's token can never ride persona B's concurrent request.
        if self.spec.auth_method == "service-token":
            key = self.spec.credential_key or ""
            token = ctx.credentials.get(key)
            if token:
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
