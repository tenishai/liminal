"""Handler registry — entry-point discovery + name-keyed lookup."""

from limenal.registry.discover import (
    DiscoveryError,
    HandlerRecord,
    Registry,
    discover_handlers,
)

__all__ = [
    "DiscoveryError",
    "HandlerRecord",
    "Registry",
    "discover_handlers",
]
