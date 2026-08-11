"""The Handler Protocol and the types every handler exchanges with liminal.

These types are the contract between liminal and a handler. Anything else
the handler does internally is its own concern; what liminal cares about
is:

  - what tools you provide (`tools()`)
  - how to invoke one (`dispatch()`)
  - what credentials and metadata you advertise (`capability_card()`)

In solo mode this contract is satisfied by a Python object. In scale mode
the same shapes round-trip over stdio JSON-RPC; the model is identical at
the call site.
"""

from liminal.protocol.card import (
    ActivationMode,
    CapabilityCard,
    CardValidationError,
    validate_card,
)
from liminal.protocol.context import Context
from liminal.protocol.handler import Handler
from liminal.protocol.tool import ToolResult, ToolSpec

__all__ = [
    "ActivationMode",
    "CapabilityCard",
    "CardValidationError",
    "Context",
    "Handler",
    "ToolResult",
    "ToolSpec",
    "validate_card",
]
