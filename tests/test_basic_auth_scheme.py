"""auth_scheme="basic" + bearer_token_env: upstreams that authenticate
service accounts as Basic base64(user:secret) -- Atlassian's hosted MCP is
the motivating case -- and credentials that live in env, never in a config
file that gets reviewed and baked into images.

The encoding rule lives in exactly two places (client _auth_header, target
_authorization) and both are pinned here to the same vector.
"""

from __future__ import annotations

import base64

import pytest

from liminal.client.mcp import _auth_header
from liminal.target.config import TargetConfigError, load_target_specs
from liminal.target.http import _authorization

B64 = base64.b64encode(b"svc@example.com:tok123").decode()


def test_client_header_basic_encodes_user_secret():
    assert _auth_header("svc@example.com:tok123", "basic") == {
        "Authorization": f"Basic {B64}"
    }


def test_client_header_bearer_unchanged_and_empty_still_omitted():
    assert _auth_header("tok", "bearer") == {"Authorization": "Bearer tok"}
    assert _auth_header("", "basic") == {}


def test_target_authorization_mirrors_the_client_rule():
    assert _authorization("basic", "svc@example.com:tok123") == f"Basic {B64}"
    assert _authorization("bearer", "tok") == "Bearer tok"


def test_config_accepts_env_sourced_basic_target():
    (spec,) = load_target_specs([{
        "name": "atlassian",
        "transport": "http",
        "address": "https://mcp.example.com/v1/mcp",
        "auth_method": "bearer",
        "auth_scheme": "basic",
        "bearer_token_env": "ATLASSIAN_BASIC",
        "required_scope": "atlassian:read",
    }])
    assert spec.auth_scheme == "basic"
    assert spec.bearer_token_env == "ATLASSIAN_BASIC"


@pytest.mark.parametrize(
    "overrides, fragment",
    [
        ({"auth_scheme": "digest"}, "auth_scheme"),
        ({"auth_scheme": "basic", "auth_method": "none"}, "needs a credential"),
        (
            {"bearer_token": "x", "bearer_token_env": "Y"},
            "mutually exclusive",
        ),
        ({"bearer_token": None, "bearer_token_env": None}, "requires"),
    ],
)
def test_config_rejects_incoherent_auth(overrides, fragment):
    base = {
        "name": "t",
        "transport": "http",
        "address": "https://x/mcp",
        "auth_method": "bearer",
        "bearer_token": "tok",
    }
    raw = {**base, **overrides}
    raw = {k: v for k, v in raw.items() if v is not None}
    with pytest.raises(TargetConfigError, match=fragment):
        load_target_specs([raw])


def test_startup_reads_the_env_and_refuses_an_empty_var(monkeypatch):
    import asyncio

    from liminal.target.config import TargetSpec
    from liminal.target.http import HttpTarget

    spec = TargetSpec(
        name="atlassian",
        address="https://mcp.example.com/v1/mcp",
        auth_method="bearer",
        auth_scheme="basic",
        bearer_token_env="ATLASSIAN_BASIC",
    )
    spec.validate()
    monkeypatch.delenv("ATLASSIAN_BASIC", raising=False)
    target = HttpTarget(spec)
    with pytest.raises(RuntimeError, match="ATLASSIAN_BASIC"):
        asyncio.run(target.startup())


# --- streamable-HTTP strictness (found live against Atlassian) ----------------


def test_parse_rpc_body_handles_sse_framed_responses():
    from liminal.client.mcp import _parse_rpc_body

    class _Resp:
        headers = {"content-type": "text/event-stream; charset=utf-8"}
        text = (
            "event: message\n"
            'data: {"jsonrpc":"2.0","method":"notifications/foo","params":{}}\n'
            "\n"
            "event: message\n"
            'data: {"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'
        )

    assert _parse_rpc_body(_Resp())["result"] == {"ok": True}


def test_parse_rpc_body_plain_json_untouched():
    from liminal.client.mcp import _parse_rpc_body

    class _Resp:
        headers = {"content-type": "application/json"}

        @staticmethod
        def json():
            return {"jsonrpc": "2.0", "id": 1, "result": {}}

    assert _parse_rpc_body(_Resp()) == {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_parse_rpc_body_empty_stream_raises():
    from liminal.client.mcp import _parse_rpc_body

    class _Resp:
        headers = {"content-type": "text/event-stream"}
        text = "event: message\ndata: not-json\n"

    with pytest.raises(ValueError, match="no JSON-RPC response"):
        _parse_rpc_body(_Resp())


async def test_requests_accept_both_forms():
    import httpx

    from liminal.client.mcp import AsyncMCPClient

    seen = {}

    async def handler(request):
        seen["accept"] = request.headers.get("accept")
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": 1,
            "result": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "serverInfo": {"name": "t", "version": "0"}},
        })

    transport = httpx.MockTransport(handler)
    client = AsyncMCPClient(
        "http://gw", token_provider=lambda: "",
        http_client=httpx.AsyncClient(transport=transport),
    )
    await client.initialize()
    assert seen["accept"] == "application/json, text/event-stream"


async def test_session_id_captured_and_echoed():
    import httpx

    from liminal.client.mcp import AsyncMCPClient

    calls = []

    async def handler(request):
        calls.append({
            "session": request.headers.get("mcp-session-id"),
            "body": request.content,
        })
        if len(calls) == 1:  # initialize
            return httpx.Response(200, json={
                "jsonrpc": "2.0", "id": 1,
                "result": {"protocolVersion": "2025-03-26", "capabilities": {},
                           "serverInfo": {"name": "t", "version": "0"}},
            }, headers={"Mcp-Session-Id": "sess-42"})
        return httpx.Response(200, json={
            "jsonrpc": "2.0", "id": 2, "result": {"tools": []}})

    client = AsyncMCPClient(
        "http://gw", token_provider=lambda: "",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    await client.list_tools()
    # initialize went out sessionless; everything after echoes the id --
    # the initialized notification included.
    assert calls[0]["session"] is None
    assert all(c["session"] == "sess-42" for c in calls[1:])
    assert len(calls) >= 3  # initialize, notification, tools/list
