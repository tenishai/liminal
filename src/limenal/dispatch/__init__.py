"""Dispatch — invoke a registered handler's tool by name."""

from limenal.dispatch.local import (
    DispatchError,
    InProcessDispatcher,
    UnknownTool,
)

__all__ = ["DispatchError", "InProcessDispatcher", "UnknownTool"]
