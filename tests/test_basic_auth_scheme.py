"""auth_scheme="basic" + bearer_token_env: upstreams that authenticate
service accounts as Basic base64(user:secret) -- Atlassian's hosted MCP is
the motivating case -- and credentials that live in env, never in a config
file that gets reviewed and baked into images.

Ported from Kyle Greiner's a102d5a (PR #89). The encoding rule lives in one
function (``liminal.client.mcp.authorization_value``); the client's base
header (``_auth_header``) and the target's per-call header (``_authorization``)
both go through it and are pinned here to the same vector.
"""

from __future__ import annotations

import asyncio
import base64
import json

import httpx
import pytest

from liminal.cli import _load_targets_file
from liminal.client.mcp import AsyncMCPClient, MCPClient, _auth_header
from liminal.protocol import Context
from liminal.target.config import TargetConfigError, TargetSpec, load_target_specs
from liminal.target.http import HttpTarget, _authorization

B64 = base64.b64encode(b"svc@example.com:tok123").decode()
BASIC = f"Basic {B64}"


# ---- the encoding rule (from a102d5a) --------------------------------------


def test_client_header_basic_encodes_user_secret():
    assert _auth_header("svc@example.com:tok123", "basic") == {"Authorization": BASIC}


def test_client_header_bearer_unchanged_and_empty_still_omitted():
    assert _auth_header("tok", "bearer") == {"Authorization": "Bearer tok"}
    assert _auth_header("", "basic") == {}


def test_target_authorization_mirrors_the_client_rule():
    assert _authorization("basic", "svc@example.com:tok123") == BASIC
    assert _authorization("bearer", "tok") == "Bearer tok"


def test_unknown_scheme_is_refused_not_sent_as_bearer():
    with pytest.raises(ValueError, match="digest"):
        _authorization("digest", "tok")
    with pytest.raises(ValueError, match="digest"):
        MCPClient("http://x", token_provider=lambda: "t", auth_scheme="digest")


# ---- config (from a102d5a) -------------------------------------------------


def test_config_accepts_env_sourced_basic_target():
    (spec,) = load_target_specs([{
        "name": "atlassian",
        "transport": "http",
        "address": "https://mcp.example.com/v1",
        "auth_method": "bearer",
        "auth_scheme": "basic",
        "bearer_token_env": "ATLASSIAN_BASIC",
        "required_scope": "atlassian:read",
    }])
    assert spec.auth_scheme == "basic"
    assert spec.bearer_token_env == "ATLASSIAN_BASIC"


def test_config_default_scheme_is_bearer():
    (spec,) = load_target_specs([{
        "name": "t", "address": "https://x", "auth_method": "bearer", "bearer_token": "tok",
    }])
    assert spec.auth_scheme == "bearer"
    assert spec.bearer_token_env is None


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
        ({"bearer_token": None, "bearer_token_env": ""}, "must name an environment variable"),
    ],
)
def test_config_rejects_incoherent_auth(overrides, fragment):
    base = {
        "name": "t",
        "transport": "http",
        "address": "https://x",
        "auth_method": "bearer",
        "bearer_token": "tok",
    }
    raw = {**base, **overrides}
    raw = {k: v for k, v in raw.items() if v is not None}
    with pytest.raises(TargetConfigError, match=fragment):
        load_target_specs([raw])


def test_targets_file_with_the_new_keys_loads(tmp_path):
    """The operator report: a v0.4.0 targets file carrying these two keys was
    refused as `unknown key(s): ['auth_scheme', 'bearer_token_env']`."""
    path = tmp_path / "targets.toml"
    path.write_text(
        "config_version = 1\n\n"
        "[[target]]\n"
        'name = "atlassian"\n'
        'address = "https://mcp.example.com/v1"\n'
        'auth_method = "bearer"\n'
        'auth_scheme = "basic"\n'
        'bearer_token_env = "ATLASSIAN_BASIC"\n',
        encoding="utf-8",
    )
    (spec,) = _load_targets_file(str(path))
    assert spec.auth_scheme == "basic"
    assert spec.bearer_token_env == "ATLASSIAN_BASIC"


# ---- startup reads the env (from a102d5a) ----------------------------------


def _basic_env_spec(**over) -> TargetSpec:
    spec = TargetSpec(**{
        "name": "atlassian",
        "address": "https://mcp.example.com/v1",
        "trust": "trusted",
        "auth_method": "bearer",
        "auth_scheme": "basic",
        "bearer_token_env": "ATLASSIAN_BASIC",
        "refresh_tools_interval_seconds": 0,
        **over,
    })
    spec.validate()
    return spec


@pytest.mark.parametrize("value", [None, "", "   \n"])
def test_startup_reads_the_env_and_refuses_an_empty_var(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("ATLASSIAN_BASIC", raising=False)
    else:
        monkeypatch.setenv("ATLASSIAN_BASIC", value)
    target = HttpTarget(_basic_env_spec())
    with pytest.raises(RuntimeError, match="ATLASSIAN_BASIC"):
        asyncio.run(target.startup())


# ---- on the wire: every request carries Basic ------------------------------


def _upstream(seen: list[tuple[str, str | None]]):
    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.read())
        method = body.get("method")
        seen.append((method, request.headers.get("authorization")))
        rid = body.get("id")
        if rid is None:  # notification
            return httpx.Response(202)
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {},
                      "serverInfo": {"name": "mock", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "search", "inputSchema": {"type": "object"}}]}
        else:
            result = {"content": [{"type": "text", "text": "hit"}]}
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": result})

    return respond


ALL_METHODS = ["initialize", "notifications/initialized", "tools/list", "tools/call"]


async def test_http_target_sends_basic_on_every_call_starting_with_initialize(monkeypatch):
    monkeypatch.setenv("ATLASSIAN_BASIC", "svc@example.com:tok123")
    seen: list[tuple[str, str | None]] = []
    http = httpx.AsyncClient(transport=httpx.MockTransport(_upstream(seen)))
    target = HttpTarget(_basic_env_spec(), http_client=http)
    await target.startup()
    try:
        ctx = Context(identity="x", agent_name="x", credentials={})
        result = await target.dispatch("search", {}, ctx)
        assert result.is_error is False
    finally:
        await target.shutdown()
        await http.aclose()

    # The FIRST request is the handshake, and it already carries Basic.
    assert seen[0] == ("initialize", BASIC)
    assert [m for m, _ in seen] == ALL_METHODS
    assert all(auth == BASIC for _, auth in seen), seen


async def test_service_token_per_call_header_honours_basic():
    seen: list[tuple[str, str | None]] = []
    http = httpx.AsyncClient(transport=httpx.MockTransport(_upstream(seen)))
    spec = TargetSpec(
        name="svc", address="https://x", trust="trusted",
        auth_method="service-token", credential_key="ATL", auth_scheme="basic",
        refresh_tools_interval_seconds=0,
    )
    spec.validate()
    target = HttpTarget(spec, http_client=http)
    await target.startup()
    try:
        ctx = Context(identity="x", agent_name="x",
                      credentials={"ATL": "svc@example.com:tok123"})
        await target.dispatch("search", {}, ctx)
    finally:
        await target.shutdown()
        await http.aclose()
    assert dict(seen)["tools/call"] == BASIC


async def test_async_client_sends_basic_on_every_call():
    seen: list[tuple[str, str | None]] = []
    http = httpx.AsyncClient(transport=httpx.MockTransport(_upstream(seen)))
    client = AsyncMCPClient(
        "http://x", token_provider=lambda: "svc@example.com:tok123",
        http_client=http, auth_scheme="basic",
    )
    await client.initialize()
    await client.list_tools()
    await client.call_tool("search", {})
    await http.aclose()
    assert [m for m, _ in seen] == ALL_METHODS
    assert all(auth == BASIC for _, auth in seen), seen


def test_sync_client_sends_basic_on_every_call():
    seen: list[tuple[str, str | None]] = []
    http = httpx.Client(transport=httpx.MockTransport(_upstream(seen)))
    client = MCPClient(
        "http://x", token_provider=lambda: "svc@example.com:tok123",
        http_client=http, auth_scheme="basic",
    )
    client.initialize()
    client.list_tools()
    client.call_tool("search", {})
    http.close()
    assert [m for m, _ in seen] == ALL_METHODS
    assert all(auth == BASIC for _, auth in seen), seen
