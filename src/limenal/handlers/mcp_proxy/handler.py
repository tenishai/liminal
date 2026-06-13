"""MCPProxyHandler — forwards limenal handler calls to an upstream MCP server.

One handler instance per ProxyConfig. Implements the standard limenal
Handler protocol; the dispatcher treats it like any other handler.

Lifecycle:
  - ``startup()``: connects to the upstream, initializes the MCP
    handshake, fetches the tool catalog. Spawns a background task
    that re-fetches tools periodically so newly-added upstream tools
    show up in limenal's catalog automatically.
  - ``dispatch(tool, payload, ctx)``: resolves auth headers per
    ``auth_method``, forwards the call via the AsyncMCPClient, returns
    the upstream's result verbatim.
  - ``shutdown()``: cancels the refresh task, closes the HTTP client.

Failure modes are explicit:
  - Upstream unreachable at startup → tool catalog empty; first
    dispatch returns ToolResult.failure with a clear message.
  - Upstream returns a 4xx/5xx mid-call → ToolResult.failure with
    the upstream's error code + message.
  - Transport error mid-call → ToolResult.failure with the exception
    type. (The caller's existing retry/circuit-breaker handles the
    rest.)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from limenal.client.mcp import (
    AsyncMCPClient,
    MCPError,
    MCPRemoteError,
    ToolCallOutcome,
)
from limenal.handlers.mcp_proxy.config import ProxyConfig
from limenal.protocol import Context, ToolResult, ToolSpec

log = structlog.get_logger(__name__)


@dataclass
class MCPProxyHandler:
    """Per-upstream proxy. One instance per ProxyConfig."""

    config: ProxyConfig
    # Optional pre-built httpx client so tests can inject a MockTransport.
    http_client: httpx.AsyncClient | None = None
    # Filled in by startup(); empty until then.
    _tools: list[ToolSpec] = field(default_factory=list, init=False)
    _client: AsyncMCPClient | None = field(default=None, init=False)
    _refresh_task: asyncio.Task | None = field(default=None, init=False)
    _owned_http: bool = field(default=False, init=False)

    # ---- Handler Protocol -------------------------------------------------

    def tools(self) -> list[ToolSpec]:
        return list(self._tools)

    def capability_card(self) -> dict[str, Any]:
        return {
            "handler": self.config.prefix,
            "description": (
                f"Forwarder to {self.config.upstream_url}. Tools listed "
                "below are owned by the upstream; their behavior is the "
                "upstream's contract."
            ),
            "tools": [
                {"name": t.name, "description": t.description}
                for t in self._tools
            ],
            "activation": "always",
            "relevance_signals": list(self.config.relevance_signals),
            "credential_keys": (
                [self.config.credential_key]
                if self.config.auth_method == "service-token"
                and self.config.credential_key
                else []
            ),
            "labels": {
                "tier": "proxy",
                "transport": "http",
                "upstream_url": self.config.upstream_url,
                "auth_method": self.config.auth_method,
            },
        }

    async def dispatch(
        self, name: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        if self._client is None:
            return ToolResult.failure(
                f"proxy {self.config.prefix!r} not started (call startup() first)"
            )
        # Auth headers per mode. AsyncMCPClient's token_provider already
        # handles bearer-style auth; we set it at construction. For
        # service-token we override per call by patching the client's
        # token provider before the call. Simpler: just send the
        # appropriate header via a custom approach.
        token = self._resolve_token(ctx)

        # Temporarily swap the client's token provider — AsyncMCPClient
        # invokes `self._token()` per request.
        original = self._client._token
        self._client._token = (lambda: token) if token is not None else (lambda: "")
        try:
            outcome: ToolCallOutcome = await self._client.call_tool(name, payload)
        except MCPRemoteError as exc:
            return ToolResult.failure(
                f"upstream {self.config.prefix!r} returned error "
                f"[{exc.code}]: {exc.message}"
            )
        except MCPError as exc:
            return ToolResult.failure(
                f"upstream {self.config.prefix!r} transport error: {exc}"
            )
        finally:
            self._client._token = original

        result = ToolResult(content=list(outcome.content), is_error=outcome.is_error)
        return result

    # ---- lifecycle --------------------------------------------------------

    async def startup(self) -> None:
        """Connect to the upstream, initialize, fetch tools, schedule refresh."""
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout_seconds)
            )
            self._owned_http = True

        # Token provider — the bearer case uses the configured static token;
        # the service-token case is patched per call in dispatch (see above).
        # The "none" case still returns an empty string so AsyncMCPClient is
        # happy; the header is skipped at the request layer when empty.
        if self.config.auth_method == "bearer" and self.config.bearer_token:
            token = self.config.bearer_token
        else:
            token = ""

        self._client = AsyncMCPClient(
            base_url=self.config.upstream_url,
            token_provider=lambda t=token: t,
            http_client=self.http_client,
            client_name=self.config.client_name,
        )

        await self._refresh_tools_once(initialize=True)

        if self.config.refresh_tools_interval_seconds > 0:
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
        if self._owned_http and self.http_client is not None:
            await self.http_client.aclose()
            self.http_client = None
            self._owned_http = False

    # ---- internals --------------------------------------------------------

    def _resolve_token(self, ctx: Context) -> str | None:
        """Return the token to send to the upstream for this dispatch."""
        method = self.config.auth_method
        if method == "none":
            return None
        if method == "bearer":
            return self.config.bearer_token
        if method == "service-token":
            key = self.config.credential_key or ""
            return ctx.credentials.get(key)
        return None

    async def _refresh_tools_once(self, *, initialize: bool = False) -> None:
        if self._client is None:
            return
        try:
            if initialize:
                await self._client.initialize()
            tools_from_upstream = await self._client.list_tools()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "mcp_proxy.refresh_failed",
                prefix=self.config.prefix,
                error=str(exc),
            )
            return
        # Convert from limenal.client.Tool to ToolSpec.
        self._tools = [
            ToolSpec(
                name=t.name,
                description=t.description,
                input_schema=t.input_schema
                or {"type": "object", "properties": {}},
            )
            for t in tools_from_upstream
        ]
        log.info(
            "mcp_proxy.tools_refreshed",
            prefix=self.config.prefix,
            count=len(self._tools),
        )

    async def _refresh_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.config.refresh_tools_interval_seconds)
                await self._refresh_tools_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception(
                    "mcp_proxy.refresh_loop_exception",
                    prefix=self.config.prefix,
                )
