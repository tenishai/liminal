"""Scratchpad — per-agent ephemeral key/value notes.

Simplest possible reference handler: no external service, no credentials,
just an in-memory dict keyed by (identity, agent_name) so the operator
can verify the full handler protocol round-trip without configuring
anything.

Real handlers (slack, github, web) follow the same shape — replace the
in-memory dict with a real backend, declare `credential_keys`, drop in.
"""

from __future__ import annotations

from typing import Any

from liminal.protocol import Context, Handler, ToolResult, ToolSpec

CARD = {
    "handler": "scratchpad",
    "required_scope": None,  # ephemeral, process-local notes — no scope gate
    "description": (
        "Per-agent ephemeral key/value notes (process-local; cleared on restart). "
        "With auth off, per MCP session."
    ),
    "tools": [
        {"name": "set", "description": "Store a value under a key"},
        {"name": "get", "description": "Retrieve a value by key (returns null if absent)"},
        {"name": "list", "description": "List all keys for this agent"},
        {"name": "clear", "description": "Delete all keys for this agent"},
    ],
    "activation": "always",
    "credential_keys": [],
    "labels": {"tier": "builtin", "persistence": "process-local"},
}


class ScratchpadHandler:
    """Pure in-memory implementation. Process-local — restart wipes."""

    def __init__(self) -> None:
        # (identity, agent_name) -> {key -> value}
        self._notes: dict[tuple[str, str], dict[str, Any]] = {}

    def tools(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="set",
                description="Store a value under a key for this agent.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "key": {"type": "string"},
                        "value": {},
                    },
                    "required": ["key", "value"],
                },
            ),
            ToolSpec(
                name="get",
                description="Get the value stored under a key (or null).",
                input_schema={
                    "type": "object",
                    "properties": {"key": {"type": "string"}},
                    "required": ["key"],
                },
            ),
            ToolSpec(
                name="list",
                description="List all keys stored for this agent.",
                input_schema={"type": "object", "properties": {}},
            ),
            ToolSpec(
                name="clear",
                description="Delete all stored notes for this agent.",
                input_schema={"type": "object", "properties": {}},
            ),
        ]

    def capability_card(self) -> dict[str, Any]:
        return CARD

    async def dispatch(
        self, name: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        # Under auth-off every caller is "anonymous"; the MCP session id the
        # server put in extra keeps each client's notes apart (liminal#192). A
        # client that sends no session id shares the anonymous bucket.
        bucket_key = (ctx.identity, ctx.agent_name, ctx.extra.get("mcp.session_id"))
        bucket = self._notes.setdefault(bucket_key, {})

        if name == "set":
            key = payload.get("key")
            if not isinstance(key, str) or not key:
                return ToolResult.failure("'key' must be a non-empty string")
            bucket[key] = payload.get("value")
            return ToolResult.text(f"set {key!r}")
        if name == "get":
            key = payload.get("key")
            if not isinstance(key, str):
                return ToolResult.failure("'key' must be a string")
            return ToolResult.json({"value": bucket.get(key)})
        if name == "list":
            return ToolResult.json({"keys": sorted(bucket.keys())})
        if name == "clear":
            count = len(bucket)
            bucket.clear()
            return ToolResult.text(f"cleared {count} key(s)")

        return ToolResult.failure(f"unknown tool {name!r}")


def get_handler() -> Handler:
    """Entry-point factory. Returns a fresh instance per app."""
    return ScratchpadHandler()
