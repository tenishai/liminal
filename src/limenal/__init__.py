"""limenal — MCP gateway."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("limenal")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

from limenal.protocol import (
    CapabilityCard,
    Context,
    Handler,
    ToolResult,
    ToolSpec,
)

__all__ = [
    "CapabilityCard",
    "Context",
    "Handler",
    "ToolResult",
    "ToolSpec",
    "__version__",
]
