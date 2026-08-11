"""Typed federated targets — the multiplexer's routing units.

A ``Target`` is a named backend with a transport. In-process handlers become
``InProcessTarget`` s; HTTP MCP upstreams become ``HttpTarget`` s. The
``Multiplexer`` (in ``liminal.dispatch``) holds targets by name and preserves
the ``{target}.{tool}`` prefixing / authz seam.
"""

from liminal.target.base import Target, TrustTier
from liminal.target.config import (
    TargetConfigError,
    TargetSpec,
    load_target_specs,
)
from liminal.target.http import HttpTarget, build_http_targets
from liminal.target.inprocess import InProcessTarget
from liminal.target.inspect import inspect_catalog, scan_tool

__all__ = [
    "HttpTarget",
    "InProcessTarget",
    "Target",
    "TargetConfigError",
    "TargetSpec",
    "TrustTier",
    "build_http_targets",
    "inspect_catalog",
    "load_target_specs",
    "scan_tool",
]
