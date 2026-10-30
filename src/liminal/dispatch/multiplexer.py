"""``Multiplexer`` — routes prefixed tool calls to named targets.

This is the generalization of ``InProcessDispatcher``: instead of holding a
``Registry`` of in-process handlers, it holds a set of ``Target`` s by name.
An in-process handler is wrapped in an ``InProcessTarget`` (via
``from_registry``); ``HttpTarget`` (and, in Stage B, ``StdioTarget``) plug
into the same map.

The public surface is preserved verbatim so the federation authz seam stays
intact (guarded by ``test_dispatch_contract.py``):

  - ``list_tools()`` returns dicts whose ``name`` is ``"{target}.{tool}"`` —
    the same prefix scheme ``InProcessDispatcher`` produces, so ``routes.py``
    still recovers the authz key with ``name.split(".")[0]``.
  - ``dispatch(*, tool_name, payload, ctx)`` splits on ``.`` and routes to the
    named target — the same keyword signature ``routes.py`` calls.
  - The authz key stays ``tool_name.split(".")[0] == target.name == registry key``.

``list_tools`` is ``async`` here (targets fetch their catalogs asynchronously —
an ``HttpTarget`` refreshes over the network). ``InProcessDispatcher`` keeps its
synchronous ``list_tools`` unchanged so its own direct callers (and the
contract tests that construct it directly) are untouched.
"""

from __future__ import annotations

from typing import Any

import structlog

from liminal.dispatch.local import DispatchError, UnknownTool, raised_failure
from liminal.protocol import Context, ToolResult
from liminal.registry import Registry
from liminal.target.base import Target
from liminal.target.inprocess import InProcessTarget

log = structlog.get_logger(__name__)

TOOL_NAME_SEPARATOR = "."


class Multiplexer:
    """Holds targets by name; prefixes catalogs and routes dispatch."""

    def __init__(self, targets: list[Target]) -> None:
        self._targets: dict[str, Target] = {}
        for target in targets:
            if target.name in self._targets:
                log.warning(
                    "multiplexer.duplicate_target",
                    name=target.name,
                    msg="last one wins",
                )
            self._targets[target.name] = target
        # Targets whose startup() raised, by name -> fixed status text. Read by
        # /healthz so a target that failed to start reads as degraded (#86).
        self.startup_failures: dict[str, str] = {}

    @classmethod
    def from_registry(cls, registry: Registry) -> Multiplexer:
        """Wrap every registered in-process handler as an ``InProcessTarget``.

        Preserves registry iteration order so ``list_tools`` and lifecycle
        ordering match the pre-refactor ``InProcessDispatcher`` behavior.
        """
        targets: list[Target] = [
            InProcessTarget(name=record.name, handler=record.handler)
            for record in registry
        ]
        return cls(targets)

    @property
    def targets(self) -> dict[str, Target]:
        return dict(self._targets)

    def add_target(self, target: Target) -> Target | None:
        """Register (or replace) a target under its name while serving
        (liminal#222). The caller has started it; the one it replaces is
        returned for the caller to shut down. Any startup failure recorded
        for the name is cleared: it described the old target."""
        old = self._targets.get(target.name)
        self._targets[target.name] = target
        self.startup_failures.pop(target.name, None)
        return old

    def remove_target(self, name: str) -> Target | None:
        """Unregister a target while serving; the caller shuts it down."""
        self.startup_failures.pop(name, None)
        return self._targets.pop(name, None)

    async def startup(self) -> None:
        """Start every target in registration order.

        One target's failure does not stop the others (#86). This loop had no
        guard, so a single hostile upstream that made its own startup raise
        took down every target after it, in-process handlers included — the
        request path has the blanket ``except`` in ``dispatch`` below, and
        startup had nothing. A failed target stays registered, so ``shutdown``
        still releases whatever it opened, and is reported on /healthz.
        """
        for name, target in self._targets.items():
            try:
                await target.startup()
            except Exception as exc:  # noqa: BLE001
                self.startup_failures[name] = "startup failed"
                log.error(
                    "multiplexer.target_startup_failed",
                    target=name,
                    error_type=type(exc).__name__,
                    error=str(exc)[:200],
                )

    async def shutdown(self) -> None:
        """Shut down every target in reverse registration order."""
        for target in reversed(list(self._targets.values())):
            await target.shutdown()

    async def list_tools(self) -> list[dict[str, Any]]:
        """All tools across all targets, prefixed ``"{target}.{tool}"``.

        Same shape as ``InProcessDispatcher.list_tools`` — a list of dicts
        with a ``name`` field carrying the ``{target}.`` prefix.
        """
        out: list[dict[str, Any]] = []
        for name, target in self._targets.items():
            for tool in await target.list_tools():
                spec = tool.model_dump(by_alias=True)
                spec["name"] = f"{name}{TOOL_NAME_SEPARATOR}{tool.name}"
                out.append(spec)
        return out

    async def dispatch(
        self,
        *,
        tool_name: str,
        payload: dict[str, Any],
        ctx: Context,
    ) -> ToolResult:
        """Split ``tool_name`` on ``.`` and route to the named target.

        Routing errors (missing prefix, unknown target) raise
        ``DispatchError`` / ``UnknownTool`` — the caller maps them to
        MCP-level errors. Once a target is selected, an exception it raises
        is caught and converted to ``ToolResult.failure`` (identical message
        format to ``InProcessDispatcher``) so the agent always sees a
        structured result. The failure names the exception class and carries
        a short error id that also appears on the log line; the exception's
        message goes to the log only (#193).
        """
        target_name, _, local_name = tool_name.partition(TOOL_NAME_SEPARATOR)
        if not local_name:
            raise DispatchError(
                f"tool name {tool_name!r} must be prefixed with target "
                f"name (e.g., 'scratchpad.set')"
            )
        target = self._targets.get(target_name)
        if target is None:
            raise UnknownTool(
                f"no target registered for prefix {target_name!r}"
            )
        try:
            return await target.dispatch(local_name, payload, ctx)
        except Exception as exc:  # noqa: BLE001
            return raised_failure(
                "multiplexer.target_raised",
                f"{target_name}.{local_name}",
                exc,
                target=target_name,
                tool=local_name,
            )
