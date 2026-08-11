"""LibraryLiminalClient — in-process LiminalClient impl.

Wraps an InProcessDispatcher and a Registry. Callers (cabal solo-mode
daemons, scripts, notebooks, tests) get the same `list_tools` /
`call_tool` surface as the proxy client without spinning up an HTTP
server.

Trust model: same-process. The library client does NOT enforce JWT,
does NOT validate scope, does NOT clamp tool_extras. If the caller
passes a Context, that Context is taken at face value. If not, a
trusted-process default Context is constructed. For multi-tenant or
sandbox-required deployments, use ProxyLiminalClient instead.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from liminal.client.mcp import Tool, ToolCallOutcome
from liminal.dispatch.local import InProcessDispatcher
from liminal.protocol.context import Context
from liminal.registry import Registry
from liminal.wire import to_spec_content

__all__ = ["LibraryLiminalClient"]

CredentialResolver = Callable[[str, str], Awaitable[dict[str, str]]]


class LibraryLiminalClient:
    """In-process LiminalClient — call handlers without HTTP."""

    def __init__(
        self,
        registry: Registry,
        *,
        default_identity: str = "library",
        default_agent_name: str = "library",
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        """
        Args:
            registry: pre-populated Registry. Use ``discover_handlers()`` to
                build one from installed entry-points.
            default_identity: persona name used in the default Context when
                the caller doesn't pass one explicitly.
            default_agent_name: agent name used in the default Context.
            credential_resolver: optional async callable ``(identity, handler)
                -> credentials_dict``. Invoked per dispatch when the caller
                doesn't supply a Context with pre-resolved credentials.
        """
        self._registry = registry
        self._dispatcher = InProcessDispatcher(registry=registry)
        self._default_identity = default_identity
        self._default_agent_name = default_agent_name
        self._credential_resolver = credential_resolver

    async def list_tools(self) -> list[Tool]:
        """Return every tool from every registered handler.

        InProcessDispatcher gives us raw dicts; convert to the same
        ``Tool`` dataclass shape AsyncMCPClient returns so caller code is
        backend-agnostic.
        """
        out: list[Tool] = []
        for spec in self._dispatcher.list_tools():
            out.append(
                Tool(
                    name=spec["name"],
                    description=spec.get("description", ""),
                    input_schema=spec.get("input_schema")
                    or spec.get("inputSchema")
                    or {"type": "object", "properties": {}},
                )
            )
        return out

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        ctx: Context | None = None,
    ) -> ToolCallOutcome:
        """Dispatch in-process. Constructs Context if not supplied."""
        resolved_ctx = ctx if ctx is not None else await self._default_ctx(name)
        result = await self._dispatcher.dispatch(
            tool_name=name,
            payload=arguments or {},
            ctx=resolved_ctx,
        )
        # ToolResult → ToolCallOutcome wire shape. The MCP-spec content
        # conversion is the same one the HTTP route applies, so both
        # backends present identical wire-format content to callers.
        return ToolCallOutcome(
            content=to_spec_content(list(result.content)),
            is_error=result.is_error,
        )

    async def aclose(self) -> None:
        """No-op — library mode owns no external resources."""
        return None

    async def _default_ctx(self, tool_name: str) -> Context:
        """Build a trusted-process default Context for a dispatch."""
        handler_name, _, _ = tool_name.partition(".")
        if self._credential_resolver is not None:
            credentials = await self._credential_resolver(
                self._default_identity, handler_name
            )
        else:
            credentials = {}
        return Context(
            identity=self._default_identity,
            agent_name=self._default_agent_name,
            credentials=credentials,
        )
