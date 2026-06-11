"""MCP protocol types — JSON-RPC envelope + MCP-specific request/result shapes.

MCP is JSON-RPC 2.0 with a small set of method names. We support the subset
limenal needs to be a usable gateway in v1:

  initialize           handshake — client declares capabilities, server reciprocates
  notifications/initialized  client confirms init; server treats as a one-way notify
  tools/list           return the dispatcher's prefixed tool surface
  tools/call           invoke a named tool with arguments
  ping                 keep-alive (server echoes)

Streaming (notifications during a long-running tool call) is a Phase 2
concern — limenal v1 returns single JSON responses per request.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# ---- JSON-RPC envelope ------------------------------------------------------


# Standard JSON-RPC 2.0 codes
ERROR_PARSE = -32700
ERROR_INVALID_REQUEST = -32600
ERROR_METHOD_NOT_FOUND = -32601
ERROR_INVALID_PARAMS = -32602
ERROR_INTERNAL = -32603

# limenal-defined (server range -32000..-32099)
ERROR_UNAUTHORIZED = -32001
ERROR_UNKNOWN_TOOL = -32002
ERROR_HANDLER_QUARANTINED = -32003


class _Open(BaseModel):
    model_config = ConfigDict(extra="allow")


class JSONRPCRequest(_Open):
    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int | None = None
    method: str
    params: dict[str, Any] | None = None


class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Any | None = None


class JSONRPCResponse(BaseModel):
    jsonrpc: Literal["2.0"] = "2.0"
    id: str | int | None = None
    result: Any | None = None
    error: JSONRPCError | None = None

    model_config = ConfigDict(extra="forbid")


def make_error(
    *, id: str | int | None, code: int, message: str, data: Any | None = None
) -> JSONRPCResponse:
    return JSONRPCResponse(id=id, error=JSONRPCError(code=code, message=message, data=data))


def make_success(*, id: str | int | None, result: Any) -> JSONRPCResponse:
    return JSONRPCResponse(id=id, result=result)


# ---- MCP method-specific shapes --------------------------------------------


class ServerInfo(_Open):
    name: str
    version: str


class InitializeParams(_Open):
    """`initialize` request params per MCP spec.

    protocolVersion is a date string per the spec ("2025-03-26"). We
    accept what the client sends and echo back a server-side version
    so the handshake is symmetric.
    """

    protocolVersion: str = Field(default="2025-06-18")
    clientInfo: dict[str, Any] | None = None
    capabilities: dict[str, Any] | None = None


class InitializeResult(_Open):
    protocolVersion: str
    serverInfo: ServerInfo
    capabilities: dict[str, Any] = Field(
        default_factory=lambda: {"tools": {"listChanged": False}}
    )


class ToolsListResult(_Open):
    tools: list[dict[str, Any]]
    nextCursor: str | None = None


class ToolCallParams(_Open):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolCallResult(_Open):
    """The MCP shape for a tool's response.

    `content` is the array of content blocks the MCP spec defines; limenal's
    ToolResult.content matches it 1:1 (`{type: "text"|"json"|..., ...}`).
    `isError` mirrors `is_error` in ToolResult.
    """

    content: list[dict[str, Any]]
    isError: bool = False
