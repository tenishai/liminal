"""Credentials liminal sent upstream are masked out of what comes back (#261)."""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote

import httpx
import pytest

from liminal.protocol import Context
from liminal.target import HttpTarget, TargetSpec
from liminal.target.mask import MASK, MIN_MASK_LENGTH, mask_content, mask_text, with_encodings

TOKEN = "tok/en+with=odd&chars\"1234"
BASIC = "ops@example.com:api-secret-5678"


# ---- the masker -------------------------------------------------------------


def test_with_encodings_covers_the_common_forms() -> None:
    forms = with_encodings([TOKEN])
    b64 = base64.b64encode(TOKEN.encode()).decode()
    for expected in (
        TOKEN,
        b64,
        b64.rstrip("="),
        base64.urlsafe_b64encode(TOKEN.encode()).decode(),
        quote(TOKEN, safe=""),
        json.dumps(TOKEN)[1:-1],
    ):
        assert expected in forms, expected
    assert forms == sorted(forms, key=len, reverse=True)


def test_basic_credential_is_masked_whole_and_by_its_secret() -> None:
    forms = with_encodings([BASIC])
    assert BASIC in forms
    assert "api-secret-5678" in forms
    assert base64.b64encode(BASIC.encode()).decode() in forms
    # The user half is not a secret on its own.
    assert "ops@example.com" not in forms


def test_short_values_are_not_masked() -> None:
    assert with_encodings(["x" * (MIN_MASK_LENGTH - 1), ""]) == []


def test_mask_content_walks_nested_content_and_counts() -> None:
    content: list[Any] = [
        {"type": "text", "text": f"auth was Bearer {TOKEN}"},
        {"type": "resource", "resource": {"text": f"echo {quote(TOKEN, safe='')}", TOKEN: 1}},
        7,
    ]
    masked, hits = mask_content(content, with_encodings([TOKEN]))
    assert hits == 3
    assert TOKEN not in json.dumps(masked)
    assert masked[0]["text"] == f"auth was Bearer {MASK}"
    assert masked[2] == 7


def test_mask_text_with_no_secrets_is_unchanged() -> None:
    assert mask_text("plain", []) == ("plain", 0)


# ---- end to end through HttpTarget -----------------------------------------


def _echoing_upstream(mode: str) -> httpx.AsyncClient:
    """An upstream whose tools/call echoes the request headers: in the result
    (mode "result"), in a JSON-RPC error (mode "rpc-error"), or in a 500 body
    (mode "http-500")."""

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.read())
        rid, method = body.get("id"), body.get("method")
        if method == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2025-06-18", "serverInfo": {"name": "m", "version": "1"},
                "capabilities": {}}})
        if method == "tools/list":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {"tools": [
                {"name": "echo", "description": "Echo.", "inputSchema": {"type": "object"}}]}})
        echoed = json.dumps(dict(request.headers))
        if mode == "result":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": echoed}]}})
        if mode == "rpc-error":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid,
                                             "error": {"code": -32000, "message": echoed}})
        return httpx.Response(500, text=f"debug: {request.headers.get('authorization')}")

    class _T(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return respond(request)

    return httpx.AsyncClient(transport=_T())


def _spec(**over: Any) -> TargetSpec:
    base: dict[str, Any] = dict(
        name="up", transport="http", address="http://test", trust="trusted",
        auth_method="service-token", credential_key="K", refresh_tools_interval_seconds=0,
    )
    base.update(over)
    return TargetSpec(**base)


async def _call(spec: TargetSpec, mode: str, credentials: dict[str, str]) -> str:
    target = HttpTarget(spec, http_client=_echoing_upstream(mode))
    await target.startup()
    try:
        result = await target.dispatch("echo", {}, Context(identity="p", agent_name="p",
                                                            credentials=credentials))
    finally:
        await target.shutdown()
    return json.dumps(result.content) + (result.error or "")


@pytest.mark.asyncio
@pytest.mark.parametrize("trust", ["trusted", "untrusted"])
@pytest.mark.parametrize("mode", ["result", "rpc-error", "http-500"])
async def test_service_token_never_comes_back(trust: str, mode: str) -> None:
    seen = await _call(_spec(trust=trust), mode, {"K": TOKEN})
    assert TOKEN not in seen
    assert json.dumps(TOKEN)[1:-1] not in seen
    assert MASK in seen


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["result", "rpc-error", "http-500"])
async def test_basic_credential_never_comes_back_encoded(mode: str) -> None:
    seen = await _call(_spec(auth_scheme="basic"), mode, {"K": BASIC})
    assert base64.b64encode(BASIC.encode()).decode() not in seen
    assert "api-secret-5678" not in seen
    assert MASK in seen


@pytest.mark.asyncio
async def test_service_headers_and_static_bearer_never_come_back() -> None:
    seen = await _call(
        _spec(auth_method="service-headers", credential_key=None,
              credential_headers={"X-Api-Key": "H"}),
        "result", {"H": "header-secret-9012"},
    )
    assert "header-secret-9012" not in seen and MASK in seen

    seen = await _call(
        _spec(auth_method="bearer", credential_key=None, bearer_token="static-bearer-3456"),
        "result", {},
    )
    assert "static-bearer-3456" not in seen and MASK in seen


@pytest.mark.asyncio
async def test_ordinary_results_pass_through() -> None:
    seen = await _call(_spec(), "result", {"K": TOKEN})
    # The non-secret echoed headers are still there.
    assert "x-liminal-correlation-id" in seen.lower() or "content-type" in seen.lower()
