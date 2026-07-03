"""Typed federated targets — the multiplexer's routing units.

A ``Target`` is a named backend with a transport. In-process handlers become
``InProcessTarget`` s; HTTP MCP upstreams become ``HttpTarget`` s. The
``Multiplexer`` (in ``limenal.dispatch``) holds targets by name and preserves
the ``{target}.{tool}`` prefixing / authz seam.
"""

from limenal.target.base import Target, TrustTier
from limenal.target.config import (
    TargetConfigError,
    TargetSpec,
    load_target_specs,
)
from limenal.target.http import HttpTarget, build_http_targets
from limenal.target.inprocess import InProcessTarget
from limenal.target.inspect import inspect_catalog, scan_tool

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
