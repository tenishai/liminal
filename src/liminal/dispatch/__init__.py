"""Dispatch — invoke a registered target's tool by name.

``InProcessDispatcher`` is the original registry-only dispatcher (kept intact
for direct callers and the contract tripwire). ``Multiplexer`` generalizes it
over typed ``Target`` s and is what ``create_app`` wires in.
"""

from liminal.dispatch.local import (
    DispatchError,
    InProcessDispatcher,
    UnknownTool,
)
from liminal.dispatch.multiplexer import Multiplexer

__all__ = ["DispatchError", "InProcessDispatcher", "Multiplexer", "UnknownTool"]
