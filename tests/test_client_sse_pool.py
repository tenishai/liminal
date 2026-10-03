"""Connection reuse after an SSE reply (liminal#132), against a real server.

httpx.MockTransport has no connection pool, so these tests run a local
uvicorn/Starlette MCP server that answers every JSON-RPC request in SSE (the
initialized notification gets a bare 202) and record the client port of each
request. One port across N sequential requests means the
connection went back to the pool after each reply; under the PR #131
behaviour almost every request took a new port (13 requests, 12 ports),
because the client stopped reading before the chunked terminator and
httpcore closed the connection.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

from liminal.client import AsyncMCPClient, MCPClient

INIT_RESULT = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}
TOOLS = {"tools": [{"name": "get_me", "description": "Who am I", "inputSchema": {"type": "object"}}]}
CALLS = 10
DRAIN = 0.2


class SSEServer:
    """An MCP server on 127.0.0.1 that answers in SSE and logs (method, client port).

    ``hold_open`` keeps each stream open after the reply with ``: ping`` comments
    until the client goes away, as a server that expects to push more would.
    """

    def __init__(self, *, hold_open: bool = False) -> None:
        self.hold_open = hold_open
        self.log: list[tuple[str, int]] = []
        app = Starlette(routes=[Route("/mcp", self._mcp, methods=["POST"])])
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning",
                                lifespan="off", timeout_graceful_shutdown=1)
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    async def _mcp(self, request: Request) -> Response:
        payload = json.loads(await request.body())
        method = payload.get("method")
        self.log.append((method, request.client.port))
        if method == "notifications/initialized":
            return Response(status_code=202)
        result = INIT_RESULT if method == "initialize" else TOOLS if method == "tools/list" else {}
        reply = json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result})

        async def events():
            yield f"event: message\ndata: {reply}\n\n"
            while self.hold_open:
                await asyncio.sleep(0.05)
                yield ": ping\n\n"

        return StreamingResponse(events(), media_type="text/event-stream")

    def __enter__(self) -> SSEServer:
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            assert time.monotonic() < deadline, "uvicorn did not start"
            time.sleep(0.01)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        return self

    def __exit__(self, *exc) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)

    def ports(self, method: str | None = None) -> list[int]:
        return [port for m, port in self.log if method is None or m == method]


def _sync_calls(url: str, **kw) -> None:
    with MCPClient(url, token_provider=lambda: "", **kw) as c:
        c.list_tools()
        for _ in range(CALLS):
            c.call_tool("get_me")


async def _async_calls(url: str, **kw) -> None:
    async with AsyncMCPClient(url, token_provider=lambda: "", **kw) as c:
        await c.list_tools()
        for _ in range(CALLS):
            await c.call_tool("get_me")


def _run(client: str, url: str, **kw) -> None:
    if client == "sync":
        _sync_calls(url, **kw)
    else:
        asyncio.run(_async_calls(url, **kw))


@pytest.mark.parametrize("client", ["sync", "async"])
def test_sequential_sse_requests_reuse_one_connection(client):
    with SSEServer() as server:
        _run(client, server.url)
    # initialize + notification + tools/list + CALLS tools/call, all on one client
    assert len(server.log) == CALLS + 3
    assert len(set(server.ports())) == 1, server.log


@pytest.mark.parametrize("client", ["sync", "async"])
def test_a_stream_held_open_costs_at_most_the_drain_timeout(client):
    """A server that never ends the stream: each call returns about DRAIN after
    its reply, every later call still works, and the half-read connection is
    never handed back to the pool, so no later request lands on its port."""
    with SSEServer(hold_open=True) as server:
        started = time.monotonic()
        _run(client, server.url, sse_drain_timeout=DRAIN)
        elapsed = time.monotonic() - started
    sse_calls = CALLS + 2  # initialize, tools/list, tools/call x CALLS
    assert len(server.log) == sse_calls + 1
    # Generous slack for a loaded CI box; a hang would be the 30 s read timeout.
    assert elapsed < sse_calls * (DRAIN + 0.5), elapsed
    for i, (method, port) in enumerate(server.log):
        if method != "notifications/initialized":
            later = [p for _, p in server.log[i + 1:]]
            assert port not in later, server.log


@pytest.mark.parametrize("client", ["sync", "async"])
def test_a_zero_drain_timeout_restores_the_stop_at_the_reply_behaviour(client):
    with SSEServer(hold_open=True) as server:
        started = time.monotonic()
        _run(client, server.url, sse_drain_timeout=0)
        elapsed = time.monotonic() - started
    assert len(server.log) == CALLS + 3
    assert elapsed < 5, elapsed

