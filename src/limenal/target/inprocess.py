"""``InProcessTarget`` — adapts an existing ``Handler`` to the ``Target`` protocol.

This is a thin, behavior-neutral adapter: no handler code changes. It maps
the synchronous ``Handler.tools()`` onto the async ``Target.list_tools()``,
forwards ``dispatch`` verbatim, and delegates ``startup``/``shutdown`` to the
handler when it defines them (some handlers open pooled clients at startup).

An in-process handler runs in this process under the operator's own control,
so it is always ``TrustTier.TRUSTED`` — its catalog is never scanned.
There is no wire protocol, so ``protocol_version`` is ``None``.
"""

from __future__ import annotations

from typing import Any

import structlog

from limenal.protocol import Context, Handler, ToolResult, ToolSpec
from limenal.target.base import Target, TrustTier

log = structlog.get_logger(__name__)


class InProcessTarget(Target):
    """Wrap a ``Handler`` so the Multiplexer can treat it as a Target."""

    def __init__(self, name: str, handler: Handler) -> None:
        self.name = name
        self.trust = TrustTier.TRUSTED
        self._handler = handler

    async def startup(self) -> None:
        # Delegate to the handler only if it defines a lifecycle hook.
        startup = getattr(self._handler, "startup", None)
        if callable(startup):
            log.debug("inprocess_target.startup", target=self.name)
            await startup()

    async def shutdown(self) -> None:
        shutdown = getattr(self._handler, "shutdown", None)
        if callable(shutdown):
            log.debug("inprocess_target.shutdown", target=self.name)
            await shutdown()

    async def list_tools(self) -> list[ToolSpec]:
        # Handler.tools() is synchronous and always live (no startup needed),
        # so this is a plain passthrough — the catalog is never stale.
        return list(self._handler.tools())

    async def dispatch(
        self, tool: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        log.debug("inprocess_target.dispatch", target=self.name, tool=tool)
        return await self._handler.dispatch(tool, payload, ctx)

    def protocol_version(self) -> str | None:
        return None
