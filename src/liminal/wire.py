"""Wire-format helpers shared by the server (HTTP routes) and the
library client. Keeps the on-the-wire shape identical regardless of
which transport delivered the result."""

from __future__ import annotations

import json
from typing import Any

__all__ = ["to_spec_content", "to_spec_result_content"]


def to_spec_content(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert internal content blocks to MCP-spec types.

    liminal handlers use ``{"type": "json", "data": <dict>}`` for
    structured results — convenient for Python but not in the MCP spec
    (only ``text`` / ``image`` / ``resource`` are defined). Convert to
    ``{"type": "text", "text": json_string}`` so any strict third-party
    MCP client can parse the output.
    """
    out: list[dict[str, Any]] = []
    for block in blocks:
        if block.get("type") == "json":
            data = block.get("data", {})
            out.append(
                {"type": "text", "text": json.dumps(data, ensure_ascii=False)}
            )
        else:
            out.append(block)
    return out


def to_spec_result_content(
    blocks: list[dict[str, Any]],
    *,
    is_error: bool = False,
    error: str | None = None,
) -> list[dict[str, Any]]:
    """Spec content for a tool result, carrying the failure reason.

    ``ToolResult.failure`` records why a call failed in ``.error`` and
    leaves ``.content`` empty. MCP has no field for that message — a
    failed call is ``isError: true`` plus descriptive content — so
    without this the agent receives an empty failure it cannot act on
    (liminal#66).

    The message is appended rather than substituted so a handler that
    returns partial content alongside an error keeps both.
    """
    out = to_spec_content(blocks)
    if is_error and error:
        out.append({"type": "text", "text": error})
    return out
