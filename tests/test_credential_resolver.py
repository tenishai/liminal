"""CabalCoreCredentialResolver tests — driven against httpx.MockTransport."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from liminal.server.credentials import (
    DEFAULT_CACHE_TTL_SECONDS,
    CabalCoreCredentialResolver,
)


def _make_resolver(
    handler_fn,
    *,
    token_provider=lambda: "test-token",
    ttl: float = DEFAULT_CACHE_TTL_SECONDS,
) -> CabalCoreCredentialResolver:
    transport = httpx.MockTransport(handler_fn)
    client = httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(5.0))
    return CabalCoreCredentialResolver(
        cabal_url="http://cabal-test",
        token_provider=token_provider,
        http_client=client,
        cache_ttl_seconds=ttl,
    )


# ---- happy path ----------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_returns_credentials_from_cabal() -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "persona": "rook",
                "handler": "slack",
                "credentials": {"SLACK_BOT_TOKEN": "xoxb-1"},
            },
        )

    resolver = _make_resolver(handler)
    creds = await resolver.fetch("rook", "slack")
    assert creds == {"SLACK_BOT_TOKEN": "xoxb-1"}
    assert len(captured) == 1
    req = captured[0]
    assert str(req.url) == "http://cabal-test/admin/secrets/rook/slack"
    assert req.headers["authorization"] == "Bearer test-token"
    await resolver.aclose()


@pytest.mark.asyncio
async def test_fetch_caches_between_calls() -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(
            200,
            json={"credentials": {"X": str(call_count["n"])}},
        )

    resolver = _make_resolver(handler)
    creds_1 = await resolver.fetch("rook", "slack")
    creds_2 = await resolver.fetch("rook", "slack")
    assert creds_1 == creds_2 == {"X": "1"}
    assert call_count["n"] == 1  # second call hit the cache
    await resolver.aclose()


@pytest.mark.asyncio
async def test_per_persona_handler_isolation() -> None:
    """Cache entries are keyed by (persona, handler); rook's slack and
    raven's slack are NOT the same cache slot."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "credentials": {
                    "WHO": request.url.path.rsplit("/", 2)[-2]  # persona
                }
            },
        )

    resolver = _make_resolver(handler)
    rook = await resolver.fetch("rook", "slack")
    raven = await resolver.fetch("raven", "slack")
    assert rook["WHO"] == "rook"
    assert raven["WHO"] == "raven"
    assert resolver.cache_size() == 2
    await resolver.aclose()


# ---- TTL + invalidation -------------------------------------------------


@pytest.mark.asyncio
async def test_cache_expires_and_refetches() -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, json={"credentials": {"X": str(call_count["n"])}})

    resolver = _make_resolver(handler, ttl=0.0)  # immediately expired
    await resolver.fetch("rook", "slack")
    await resolver.fetch("rook", "slack")
    # TTL of 0 → every call re-fetches
    assert call_count["n"] >= 2
    await resolver.aclose()


@pytest.mark.asyncio
async def test_invalidate_busts_cache_for_one_pair() -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, json={"credentials": {"X": "y"}})

    resolver = _make_resolver(handler)
    await resolver.fetch("rook", "slack")
    await resolver.fetch("raven", "slack")
    assert call_count["n"] == 2

    resolver.invalidate("rook", "slack")
    await resolver.fetch("rook", "slack")  # re-fetch
    await resolver.fetch("raven", "slack")  # still cached
    assert call_count["n"] == 3
    await resolver.aclose()


@pytest.mark.asyncio
async def test_invalidate_all() -> None:
    call_count = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        call_count["n"] += 1
        return httpx.Response(200, json={"credentials": {"X": "y"}})

    resolver = _make_resolver(handler)
    await resolver.fetch("rook", "slack")
    await resolver.fetch("raven", "github")
    resolver.invalidate_all()
    assert resolver.cache_size() == 0
    await resolver.aclose()


# ---- failure modes ----------------------------------------------------


@pytest.mark.asyncio
async def test_transport_error_returns_empty_dict_logs_warning() -> None:
    """A network failure must not raise — must return {} so a temporarily
    unreachable Cabal doesn't black-hole every credentialed tool call."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network down")

    resolver = _make_resolver(handler)
    creds = await resolver.fetch("rook", "slack")
    assert creds == {}
    # Failed fetches are NOT cached (next call re-tries)
    assert resolver.cache_size() == 0
    await resolver.aclose()


@pytest.mark.asyncio
async def test_403_returns_empty_dict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"detail": "wrong scope"})

    resolver = _make_resolver(handler)
    creds = await resolver.fetch("rook", "slack")
    assert creds == {}
    assert resolver.cache_size() == 0
    await resolver.aclose()


@pytest.mark.asyncio
async def test_404_returns_empty_dict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="not found")

    resolver = _make_resolver(handler)
    creds = await resolver.fetch("ghost", "slack")
    assert creds == {}
    await resolver.aclose()


@pytest.mark.asyncio
async def test_non_json_response_returns_empty_dict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    resolver = _make_resolver(handler)
    creds = await resolver.fetch("rook", "slack")
    assert creds == {}
    await resolver.aclose()


@pytest.mark.asyncio
async def test_credentials_wrong_shape_returns_empty_dict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"credentials": "not-a-dict"})

    resolver = _make_resolver(handler)
    creds = await resolver.fetch("rook", "slack")
    assert creds == {}
    await resolver.aclose()


@pytest.mark.asyncio
async def test_missing_credentials_key_returns_empty_dict() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"persona": "rook", "handler": "slack"})

    resolver = _make_resolver(handler)
    creds = await resolver.fetch("rook", "slack")
    assert creds == {}
    await resolver.aclose()


# ---- token_provider behavior ------------------------------------------


@pytest.mark.asyncio
async def test_token_provider_invoked_per_fetch() -> None:
    """Each cache MISS calls the token_provider (so short-lived JWTs
    refresh transparently). Cache HITs do not."""
    mint_count = {"n": 0}

    def provider() -> str:
        mint_count["n"] += 1
        return f"jwt-{mint_count['n']}"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"credentials": {"X": "y"}})

    resolver = _make_resolver(handler, token_provider=provider)
    await resolver.fetch("rook", "slack")  # miss → mint
    await resolver.fetch("rook", "slack")  # hit → no mint
    await resolver.fetch("raven", "slack")  # miss → mint
    assert mint_count["n"] == 2
    await resolver.aclose()


# ---- end-to-end with the route ----------------------------------------


@pytest.mark.asyncio
async def test_resolver_credentials_reach_handler(
    keyset, mint_token
) -> None:
    """Wire the resolver into create_app; verify the credentials it
    returns land in Context.credentials seen by the handler."""
    from liminal.protocol import Context, ToolResult, ToolSpec
    from liminal.registry import Registry
    from liminal.registry.discover import register_explicit
    from liminal.server import StaticKeySetVerifier, create_app

    class _EchoCredsHandler:
        name = "echo-creds"

        def tools(self) -> list[ToolSpec]:
            return [ToolSpec(name="dump", description="x")]

        def capability_card(self) -> dict[str, Any]:
            return {
                "handler": "echo-creds",
                "description": "test",
                "tools": [{"name": "dump", "description": "x"}],
            }

        async def dispatch(self, name, payload, ctx: Context) -> ToolResult:
            return ToolResult.json({"creds": dict(ctx.credentials)})

    seen_persona_handler: list[tuple[str, str]] = []

    async def resolver(persona: str, handler: str) -> dict[str, str]:
        seen_persona_handler.append((persona, handler))
        return {"SECRET_KEY": f"value-for-{persona}-{handler}"}

    registry = Registry()
    register_explicit(registry, "echo-creds", _EchoCredsHandler())
    app = create_app(
        jwt_verifier=StaticKeySetVerifier(key_set=keyset),
        registry=registry,
        credential_resolver=resolver,
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        token = mint_token(persona="rook", sub="rook-primus")
        r = await c.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo-creds.dump", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    body = r.json()
    assert body.get("error") is None, body
    creds = json.loads(body["result"]["content"][0]["text"])["creds"]
    assert creds == {"SECRET_KEY": "value-for-rook-echo-creds"}
    assert seen_persona_handler == [("rook", "echo-creds")]
