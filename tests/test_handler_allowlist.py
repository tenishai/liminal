"""Phase NN — per-persona handler allowlists.

cabal_tool_extras["limenal.allowed_handlers"] is the operator-controlled
list of handlers each persona can see + call. When set:
  - tools/list filters to only handlers in the list
  - tools/call refuses handlers outside the list with -32002

When unset (None / missing / wrong shape):
  - All registered handlers visible + callable (existing behavior)
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest
from joserfc import jwt

from limenal.handlers.scratchpad import ScratchpadHandler
from limenal.protocol import ToolResult, ToolSpec
from limenal.registry import Registry
from limenal.registry.discover import register_explicit
from limenal.server import StaticKeySetVerifier, create_app


class _EchoHandler:
    """Stand-in for a second handler so we have something to filter
    against. Returns no-op JSON."""

    name = "echo-handler"

    def tools(self) -> list[ToolSpec]:
        return [ToolSpec(name="ping", description="pong")]

    def capability_card(self) -> dict[str, Any]:
        return {
            "handler": "echo-handler",
            "description": "test",
            "tools": [{"name": "ping", "description": "pong"}],
        }

    async def dispatch(self, name, payload, ctx):
        return ToolResult.json({"persona": ctx.identity})


def _mint_with_allowlist(signing_key, allowlist: list[str] | None) -> str:
    """Mint a JWT carrying limenal.allowed_handlers in cabal_tool_extras.
    Pass None to omit the allowlist entirely (= unrestricted)."""
    now = int(time.time())
    header = {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"}
    payload: dict[str, Any] = {
        "iss": "cabal-core",
        "sub": "rook-primus",
        "aud": "limenal",
        "iat": now,
        "exp": now + 60,
        "cabal_persona": "rook",
        "cabal_scope": ["dispatch"],
    }
    if allowlist is not None:
        payload["cabal_tool_extras"] = {
            "limenal.allowed_handlers": allowlist
        }
    return jwt.encode(header, payload, signing_key)


@pytest.fixture
def registry_with_two_handlers():
    r = Registry()
    register_explicit(r, "scratchpad", ScratchpadHandler())
    register_explicit(r, "echo-handler", _EchoHandler())
    return r


@pytest.fixture
def app(keyset, registry_with_two_handlers):
    return create_app(
        jwt_verifier=StaticKeySetVerifier(key_set=keyset),
        registry=registry_with_two_handlers,
    )


@pytest.fixture
def client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


# ---- tools/list filtering -------------------------------------------------


@pytest.mark.asyncio
async def test_no_allowlist_returns_all_handlers(client, signing_key) -> None:
    token = _mint_with_allowlist(signing_key, allowlist=None)
    async with client as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
    names = {t["name"] for t in r.json()["result"]["tools"]}
    # Both handlers visible
    assert any(n.startswith("scratchpad.") for n in names)
    assert any(n.startswith("echo-handler.") for n in names)


@pytest.mark.asyncio
async def test_allowlist_filters_tools_list(client, signing_key) -> None:
    token = _mint_with_allowlist(signing_key, allowlist=["scratchpad"])
    async with client as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert all(n.startswith("scratchpad.") for n in names)
    assert not any(n.startswith("echo-handler.") for n in names)


@pytest.mark.asyncio
async def test_empty_allowlist_filters_everything(client, signing_key) -> None:
    """An explicit empty list means: persona can see NO tools. Edge case
    but operationally meaningful — operator can revoke tool access
    without disabling mcp entirely."""
    token = _mint_with_allowlist(signing_key, allowlist=[])
    async with client as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.json()["result"]["tools"] == []


@pytest.mark.asyncio
async def test_malformed_allowlist_fails_closed(client, signing_key) -> None:
    """A string instead of a list is a malformed claim — fail closed (no tools)
    rather than silently fail open (all tools)."""
    now = int(time.time())
    header = {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"}
    payload = {
        "iss": "cabal-core",
        "sub": "rook-primus",
        "aud": "limenal",
        "iat": now,
        "exp": now + 60,
        "cabal_persona": "rook",
        "cabal_scope": ["dispatch"],
        "cabal_tool_extras": {"limenal.allowed_handlers": "scratchpad"},  # str, not list!
    }
    token = jwt.encode(header, payload, signing_key)
    async with client as c:
        r = await c.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {token}"},
        )
    names = {t["name"] for t in r.json()["result"]["tools"]}
    # Malformed claim → deny all; empty tool list, not full list
    assert len(names) == 0


# ---- tools/call enforcement ---------------------------------------------


@pytest.mark.asyncio
async def test_call_to_allowed_handler_succeeds(client, signing_key) -> None:
    token = _mint_with_allowlist(signing_key, allowlist=["scratchpad"])
    async with client as c:
        r = await c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "scratchpad.set",
                    "arguments": {"key": "k", "value": "v"},
                },
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    assert body.get("error") is None, body
    assert body["result"]["isError"] is False


@pytest.mark.asyncio
async def test_call_to_disallowed_handler_refused(client, signing_key) -> None:
    """Defense in depth: even if the LLM hallucinates a tool name not in
    the visible list, tools/call refuses."""
    token = _mint_with_allowlist(signing_key, allowlist=["scratchpad"])
    async with client as c:
        r = await c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "echo-handler.ping",
                    "arguments": {},
                },
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    assert body["error"]["code"] == -32002  # ERROR_UNKNOWN_TOOL
    assert "echo-handler" in body["error"]["message"]
    assert "scratchpad" in body["error"]["message"]  # lists what IS allowed


@pytest.mark.asyncio
async def test_empty_allowlist_blocks_all_calls(client, signing_key) -> None:
    token = _mint_with_allowlist(signing_key, allowlist=[])
    async with client as c:
        r = await c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "scratchpad.set",
                    "arguments": {"key": "k", "value": "v"},
                },
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    assert body["error"]["code"] == -32002


@pytest.mark.asyncio
async def test_unrestricted_persona_can_call_any_handler(
    client, signing_key
) -> None:
    """Sanity that the existing (no allowlist) behavior is preserved."""
    token = _mint_with_allowlist(signing_key, allowlist=None)
    async with client as c:
        for handler_name in ("scratchpad", "echo-handler"):
            tool = "set" if handler_name == "scratchpad" else "ping"
            args = {"key": "k", "value": "v"} if tool == "set" else {}
            r = await c.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": f"{handler_name}.{tool}",
                        "arguments": args,
                    },
                },
                headers={"Authorization": f"Bearer {token}"},
            )
            body = r.json()
            assert body.get("error") is None, body
