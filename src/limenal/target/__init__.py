"""Typed federated targets — the multiplexer's routing units.

A ``Target`` is a named backend with a transport. In-process handlers become
``InProcessTarget`` s; HTTP MCP upstreams become ``HttpTarget`` s. The
``Multiplexer`` (in ``limenal.dispatch``) holds targets by name and preserves
the ``{target}.{tool}`` prefixing / authz seam.
"""

from limenal.target.base import Target, TrustTier
from limenal.target.inprocess import InProcessTarget

__all__ = [
    "InProcessTarget",
    "Target",
    "TrustTier",
]
