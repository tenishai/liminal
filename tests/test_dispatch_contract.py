"""Dispatcher-contract characterization tests (pre-#12 tripwire).

These tests pin the CURRENT contract that the federation authz layer depends
on.  They must pass today and must continue to pass after #12's dispatch
restructuring — any breakage signals an authz-seam regression.

Specifically, the tests pin:

1. ``list_tools()`` emits ``"{handler}.{tool}"`` names so routes.py can
   derive the handler key with ``name.split(".")[0]``.
2. ``InProcessDispatcher.dispatch()`` accepts ``tool_name``, ``payload``,
   and ``ctx`` as keyword arguments — the calling convention in routes.py.
3. The handler-name recovered by ``name.split(".")[0]`` always equals the
   registry key that ``registry.get(handler_name)`` resolves.
4. A ``ScopeGrant.allowed_handlers`` on the *server-side* grant is the
   authoritative filter for both ``tools/list`` and ``tools/call`` (the
   inversion proof: the token cannot override it).
"""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient
from joserfc import jwt

from limenal.dispatch import InProcessDispatcher
from limenal.handlers.scratchpad import ScratchpadHandler
from limenal.protocol import Context, ToolResult, ToolSpec
from limenal.registry import Registry
from limenal.registry.discover import register_explicit
from limenal.server import (
    MultiIssuerJWKSVerifier,
    SqlitePolicyStore,
    StaticKeySetVerifier,
    create_app,
)

_SVC = "contract-test"


# ---------------------------------------------------------------------------
# Minimal second handler so tests have something to filter *against*.
# ---------------------------------------------------------------------------


class _EchoHandler:
    def tools(self) -> list[ToolSpec]:
        return [ToolSpec(name="ping", description="pong")]

    def capability_card(self) -> dict:
        return {
            "handler": "echo",
            "description": "echo for contract tests",
            "tools": [{"name": "ping", "description": "pong"}],
            "activation": "always",
            "relevance_signals": [],
            "credential_keys": [],
            "labels": {"tier": "test"},
        }

    async def dispatch(self, name: str, payload: dict, ctx: Context) -> ToolResult:
        return ToolResult.json({"pong": True})


def _two_handler_registry() -> Registry:
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    register_explicit(reg, "echo", _EchoHandler())
    return reg


# ---------------------------------------------------------------------------
# 1. list_tools() name format: "{handler}.{tool}"
# ---------------------------------------------------------------------------


def test_list_tools_names_are_prefixed_with_handler_name() -> None:
    """Every entry from list_tools() must be named '{handler}.{tool}'.

    routes.py derives the authz key with ``name.split('.')[0]``; a name
    without the prefix would silently break the handler allowlist check.
    """
    d = InProcessDispatcher(registry=_two_handler_registry())
    tools = d.list_tools()
    assert tools, "list_tools() must return at least one entry"
    for spec in tools:
        name = spec["name"]
        parts = name.split(".", 1)
        assert len(parts) == 2 and parts[0] and parts[1], (
            f"tool name {name!r} is not in '{{handler}}.{{tool}}' format"
        )

    # Confirm the concrete prefixes match the registry keys.
    scratchpad_names = [t["name"] for t in tools if t["name"].startswith("scratchpad.")]
    echo_names = [t["name"] for t in tools if t["name"].startswith("echo.")]
    assert scratchpad_names, "scratchpad tools must appear as 'scratchpad.*'"
    assert echo_names, "echo tools must appear as 'echo.*'"


# ---------------------------------------------------------------------------
# 2. dispatch() keyword-argument signature
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_accepts_keyword_arguments() -> None:
    """dispatch() must accept tool_name, payload, ctx as keyword args.

    routes.py calls ``dispatcher.dispatch(tool_name=…, payload=…, ctx=…)``.
    A positional-only refactor in #12 would silently break the call site.
    """
    d = InProcessDispatcher(registry=_two_handler_registry())
    ctx = Context(identity="rook", agent_name="rook-primus", credentials={})
    result = await d.dispatch(
        tool_name="scratchpad.set",
        payload={"key": "k", "value": "v"},
        ctx=ctx,
    )
    assert not result.is_error, result.error


# ---------------------------------------------------------------------------
# 3. handler_name from split(".")[0] == registry key
# ---------------------------------------------------------------------------


def test_handler_name_from_tool_name_equals_registry_key() -> None:
    """``tool_name.split('.')[0]`` always resolves in the registry.

    This is the authz seam: routes._handle_tools_call does
    ``handler_name = params.name.split('.')[0]`` then checks it against the
    allowed_handlers set.  If the registry key ever diverges from the prefix,
    authorization silently fails open.
    """
    reg = _two_handler_registry()
    d = InProcessDispatcher(registry=reg)
    for spec in d.list_tools():
        tool_name = spec["name"]
        handler_name = tool_name.split(".", 1)[0]
        record = reg.get(handler_name)
        assert record is not None, (
            f"handler_name {handler_name!r} derived from {tool_name!r} "
            "must exist in the registry"
        )
        # The registry key must equal what the split returns — no aliasing.
        assert record.name == handler_name, (
            f"registry record name {record.name!r} != derived key {handler_name!r}"
        )


# ---------------------------------------------------------------------------
# 4. PolicyStore grant.allowed_handlers filters list + call
# ---------------------------------------------------------------------------


def _mint(key, *, iss: str, persona: str = "rook", sub: str = "rook-primus", ttl: int = 60) -> str:
    now = int(time.time())
    return jwt.encode(
        {"alg": "RS256", "kid": key.kid, "typ": "JWT"},
        {
            "iss": iss,
            "sub": sub,
            "aud": _SVC,
            "iat": now,
            "exp": now + ttl,
            "cabal_persona": persona,
        },
        key,
    )


@pytest.mark.asyncio
async def test_grant_allowed_handlers_filters_list_and_call(
    tmp_path, signing_key, keyset
) -> None:
    """ScopeGrant.allowed_handlers is authoritative for both tools/list and
    tools/call — the token cannot override it (federation inversion proof).

    This pins the pre-#12 contract so restructuring cannot break it silently:
    - tools/list must hide handlers not in allowed_handlers
    - tools/call to an excluded handler must be refused (-32002)
    - tools/call to an included handler must succeed
    """
    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=keyset,
                expected_issuer="rd-cabal",
                expected_audience=_SVC,
            ),
        },
        parents=frozenset({"rd-cabal"}),
    )
    store = SqlitePolicyStore(str(tmp_path / "policy.db"), parent_issuer="rd-cabal")

    reg = _two_handler_registry()
    app = create_app(jwt_verifier=verifier, registry=reg, policy_store=store)

    # Grant rd-cabal/rook scratchpad only (echo excluded).
    await store.grant(
        "rd-cabal",
        "rook",
        scopes={"dispatch"},
        allowed_handlers={"scratchpad"},
    )
    tok = _mint(signing_key, iss="rd-cabal")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:

        # tools/list: only scratchpad visible.
        list_r = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {tok}"},
        )
        tools = list_r.json()["result"]["tools"]
        assert all(t["name"].startswith("scratchpad.") for t in tools), (
            f"tools/list must show only scratchpad tools, got: {[t['name'] for t in tools]}"
        )
        assert not any(t["name"].startswith("echo.") for t in tools), (
            "tools/list must not expose echo (excluded by grant)"
        )

        # tools/call to included handler: succeed.
        ok = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "scratchpad.set", "arguments": {"key": "k", "value": "v"}},
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert ok.json().get("error") is None, ok.json()

        # tools/call to excluded handler: refused with -32002.
        deny = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "echo.ping", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
        err = deny.json().get("error")
        assert err is not None, "echo.ping must be refused when echo is excluded"
        assert err["code"] == -32002, err
        assert "echo" in err["message"], err["message"]

    store.close()
