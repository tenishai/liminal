"""The fail-loud set (liminal#75, #76, #80) — client and target conduct.

#75: the MCP handshake authenticates like every other call, and a failed
startup catalog fetch is loud (error log, catalog_status, /healthz degraded)
instead of a silent zero-tool target. #76: the owned upstream client rejects
every cookie, so one persona's upstream session can never ride another's
call. #80: a service-token dispatch whose credential did not resolve is
refused with the missing key named, never sent upstream unauthenticated.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from liminal.client.mcp import AsyncMCPClient
from liminal.protocol import Context
from liminal.target import HttpTarget, TargetSpec


def _rpc_responder(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.read())
    rid = body.get("id")
    method = body.get("method")
    if method == "initialize":
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": "mock", "version": "1"},
                    "capabilities": {},
                },
            },
        )
    if method == "tools/list":
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": rid, "result": {"tools": []}},
        )
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {}})


class _Recorder(httpx.AsyncBaseTransport):
    def __init__(self, responder=_rpc_responder, cookie_on_first=False):
        self.responder = responder
        self.requests: list[httpx.Request] = []
        self._cookie_on_first = cookie_on_first

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request.read()
        self.requests.append(request)
        response = self.responder(request)
        if self._cookie_on_first and len(self.requests) == 1:
            response.headers["set-cookie"] = "upstream_session=persona-a; Path=/"
        return response


def _http_spec(**over: Any) -> TargetSpec:
    base: dict[str, Any] = dict(
        name="upstream",
        transport="http",
        address="http://test",
        trust="trusted",
        auth_method="none",
        refresh_tools_interval_seconds=0,
    )
    base.update(over)
    return TargetSpec(**base)


def _ctx(**over: Any) -> Context:
    base: dict[str, Any] = dict(
        identity="rook",
        agent_name="rook-primus",
        issuer="home-cabal",
        credentials={},
        extra={},
    )
    base.update(over)
    return Context(**base)


# ---- #75: the handshake authenticates -------------------------------------


@pytest.mark.asyncio
async def test_initialize_sends_authorization_when_token_present() -> None:
    recorder = _Recorder()
    client = AsyncMCPClient(
        base_url="http://test",
        token_provider=lambda: "tok-abc",
        http_client=httpx.AsyncClient(transport=recorder),
    )
    await client.initialize()
    handshake = recorder.requests[0]
    assert handshake.headers.get("authorization") == "Bearer tok-abc"


@pytest.mark.asyncio
async def test_initialize_omits_header_for_empty_token() -> None:
    """The #32 contract survives #75: no-auth mode never renders an illegal
    empty bearer."""
    recorder = _Recorder()
    client = AsyncMCPClient(
        base_url="http://test",
        token_provider=lambda: "",
        http_client=httpx.AsyncClient(transport=recorder),
    )
    await client.initialize()
    assert "authorization" not in recorder.requests[0].headers


# ---- #75: failed catalog fetch is loud ------------------------------------


def _failing_responder(request: httpx.Request) -> httpx.Response:
    return httpx.Response(500, text="upstream exploded")


@pytest.mark.asyncio
async def test_startup_catalog_failure_sets_status_not_silence() -> None:
    target = HttpTarget(
        _http_spec(),
        http_client=httpx.AsyncClient(transport=_Recorder(_failing_responder)),
    )
    await target.startup()
    try:
        assert target.catalog_status.startswith("catalog fetch failed")
        assert await target.list_tools() == []
    finally:
        await target.shutdown()


@pytest.mark.asyncio
async def test_startup_catalog_success_reads_ready() -> None:
    target = HttpTarget(
        _http_spec(), http_client=httpx.AsyncClient(transport=_Recorder())
    )
    await target.startup()
    try:
        assert target.catalog_status == "ready"
    finally:
        await target.shutdown()


@pytest.mark.asyncio
async def test_healthz_reports_a_failed_target_as_degraded() -> None:
    from httpx import ASGITransport, AsyncClient

    from liminal.handlers.scratchpad import ScratchpadHandler
    from liminal.registry import Registry
    from liminal.registry.discover import register_explicit
    from liminal.server import create_app

    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    app = create_app(registry=reg)

    class _Broken:
        name = "vendor"
        catalog_status = "catalog fetch failed: boom"

    app.state.dispatcher._targets["vendor"] = _Broken()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://t"
    ) as client:
        body = (await client.get("/healthz")).json()
    assert body["status"] == "degraded"
    assert body["targets"]["vendor"].startswith("catalog fetch failed")
    assert body["targets"]["scratchpad"] == "ready"


# ---- #76: the owned client rejects cookies ---------------------------------


@pytest.mark.asyncio
async def test_owned_client_never_replays_upstream_cookies(monkeypatch) -> None:
    """An upstream Set-Cookie on call one must not ride call two. The owned
    client is built inside startup(); we intercept construction to inject the
    recording transport while keeping the target's own cookie policy."""
    recorder = _Recorder(cookie_on_first=True)
    real_async_client = httpx.AsyncClient

    def _spy(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = recorder
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _spy)
    target = HttpTarget(_http_spec())
    await target.startup()
    try:
        await target.dispatch("ping", {}, _ctx())
    finally:
        await target.shutdown()

    assert len(recorder.requests) >= 3  # initialize, tools/list, tools/call
    later = recorder.requests[1:]
    assert all("cookie" not in r.headers for r in later), [
        dict(r.headers) for r in later
    ]


# ---- #80: missing credential refuses, never dials --------------------------


@pytest.mark.asyncio
async def test_missing_service_token_refuses_and_never_calls_upstream() -> None:
    recorder = _Recorder()
    target = HttpTarget(
        _http_spec(auth_method="service-token", credential_key="vendor_api"),
        http_client=httpx.AsyncClient(transport=recorder),
    )
    await target.startup()
    try:
        calls_before = len(recorder.requests)
        result = await target.dispatch("ping", {}, _ctx(credentials={}))
        assert result.is_error
        assert "vendor_api" in (result.error or "")
        assert "unauthenticated" in (result.error or "")
        assert len(recorder.requests) == calls_before  # nothing dialed
    finally:
        await target.shutdown()


@pytest.mark.asyncio
async def test_present_service_token_still_rides_the_call() -> None:
    recorder = _Recorder()
    target = HttpTarget(
        _http_spec(auth_method="service-token", credential_key="vendor_api"),
        http_client=httpx.AsyncClient(transport=recorder),
    )
    await target.startup()
    try:
        await target.dispatch("ping", {}, _ctx(credentials={"vendor_api": "tok-9"}))
        assert recorder.requests[-1].headers.get("authorization") == "Bearer tok-9"
    finally:
        await target.shutdown()


class _FlippableResponder:
    """Succeeds or fails per the current mode -- for the periodic-refresh
    path, where the choice (does a refresh failure degrade health?) needs a
    test pinning it: it DOES, deliberately -- a stale catalog serving an
    increasingly wrong tool surface behind a green health check is the
    failure mode liminal#75 exists to kill."""

    def __init__(self):
        self.failing = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.failing:
            return httpx.Response(500, text="refresh exploded")
        return _rpc_responder(request)


@pytest.mark.asyncio
async def test_periodic_refresh_failure_degrades_and_recovery_resets() -> None:
    responder = _FlippableResponder()
    target = HttpTarget(
        _http_spec(),
        http_client=httpx.AsyncClient(transport=_Recorder(responder)),
    )
    await target.startup()
    try:
        assert target.catalog_status == "ready"

        responder.failing = True
        await target._refresh_tools_once()
        assert target.catalog_status.startswith("catalog fetch failed")

        responder.failing = False
        await target._refresh_tools_once()
        assert target.catalog_status == "ready"
    finally:
        await target.shutdown()


@pytest.mark.asyncio
async def test_healthz_does_not_republish_upstream_bytes() -> None:
    """Prudence, #84 r1 Critical. `catalog_status` is served VERBATIM on
    /healthz, which has no auth at all — so interpolating the exception let an
    UPSTREAM choose what liminal republishes to unauthenticated callers.
    MCPTransportError embeds `resp.text[:200]` for a 5xx, so a 500 body reached
    the wire. The status must be coarse; the detail belongs in the log.
    """
    marker = "SUPERSECRET-UPSTREAM-BODY-DO-NOT-REPUBLISH"
    state = {"n": 0}

    def boom(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.read())
        if body.get("method") == "tools/list":
            state["n"] += 1
            if state["n"] > 1:                     # first fetch succeeds
                return httpx.Response(500, text=marker)
        return _rpc_responder(request)

    target = HttpTarget(
        _http_spec(), http_client=httpx.AsyncClient(transport=_Recorder(boom))
    )
    await target.startup()
    try:
        await target._refresh_tools_once()
        assert target.catalog_status.startswith("catalog fetch failed")
        assert marker not in target.catalog_status, (
            "the upstream's response body reached catalog_status, and /healthz "
            "serves that verbatim to unauthenticated callers"
        )
    finally:
        await target.shutdown()


@pytest.mark.asyncio
async def test_whitespace_credential_is_a_missing_credential() -> None:
    """Prudence, #84 r1 Important. `if not token` catches "" and None but not
    "   " — and a trailing newline is the shape a secret read from a file
    arrives in. #80's guarantee is that a missing credential is a REFUSAL, not
    an anonymous upstream call.
    """
    recorder = _Recorder(_rpc_responder)
    target = HttpTarget(
        _http_spec(auth_method="service-token", credential_key="svc"),
        http_client=httpx.AsyncClient(transport=recorder),
    )
    await target.startup()
    try:
        for bad in ("   ", "\n", "\t \n"):
            before = len(recorder.requests)
            result = await target.dispatch(
                "search", {}, _ctx(credentials={"svc": bad})
            )
            assert result.is_error, f"whitespace credential {bad!r} was accepted"
            assert "did not resolve" in (result.error or "")
            assert len(recorder.requests) == before, (
                f"a request was dialed with credential {bad!r} — #80's "
                "guarantee is that this never reaches the upstream"
            )
    finally:
        await target.shutdown()
