"""The ``Target`` abstraction — a named backend with a transport.

A ``Target`` is the unit the ``Multiplexer`` routes to. It generalizes
today's in-process handlers: an in-process handler becomes *one kind* of
target (``InProcessTarget``) alongside ``HttpTarget`` (and, in Stage B,
``StdioTarget``).

Every target satisfies one protocol:

  - ``name``   — the namespace / authz key. Equals the registry key today;
    ``list_tools`` prefixes tool names with it, and ``routes.py`` recovers
    it with ``tool_name.split(".")[0]``.  This equivalence is the
    federation authz seam guarded by ``test_dispatch_contract.py``.
  - ``trust``  — ``TRUSTED`` | ``UNTRUSTED``. Gates catalog inspection: an
    ``UNTRUSTED`` upstream's tool descriptions are scanned at ingest before
    they reach a persona's context. ``InProcessTarget`` is always TRUSTED.
  - ``startup`` / ``shutdown`` — lifecycle (open/close clients, refresh loops).
  - ``list_tools`` — this target's catalog, **UN**prefixed. The Multiplexer
    adds the ``{name}.`` prefix.
  - ``dispatch`` — invoke one (unprefixed) tool.
  - ``protocol_version`` — negotiated MCP version for diagnostics; ``None``
    for in-process targets (no wire protocol).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from limenal.protocol import Context, ToolResult, ToolSpec


class TrustTier(StrEnum):
    """Whether a target's tool catalog is trusted at ingest.

    ``TRUSTED`` — the catalog flows through verbatim (in-process handlers,
    or an operator-vouched upstream).
    ``UNTRUSTED`` — the catalog is scanned by ``inspect_catalog`` before it
    reaches a persona's context (the #16 injection-inspection chokepoint).
    """

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@runtime_checkable
class Target(Protocol):
    """A namespace with a transport. All target kinds satisfy this."""

    name: str
    trust: TrustTier

    async def startup(self) -> None:
        """Open clients / start refresh loops. Idempotent-friendly."""
        ...

    async def shutdown(self) -> None:
        """Tear down whatever ``startup`` created. Safe to call twice."""
        ...

    async def list_tools(self) -> list[ToolSpec]:
        """This target's catalog, UNprefixed. The Multiplexer prefixes."""
        ...

    async def dispatch(
        self, tool: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        """Invoke one (unprefixed) tool on this target."""
        ...

    def protocol_version(self) -> str | None:
        """Negotiated MCP protocol version, or ``None`` for in-process."""
        ...
