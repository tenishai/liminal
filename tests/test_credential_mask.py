"""Credentials liminal sent upstream are masked out of what comes back (#261)."""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote

import httpx
import pytest

from liminal.client.mcp import SERVER_ERROR_BODY_CHARS
from liminal.protocol import Context
from liminal.target import HttpTarget, TargetSpec
from liminal.target.http import CORRELATION_ID_KEY
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
        if mode == "http-500-straddle":
            # The credential straddles the 200-character cut of the 5xx body.
            auth = request.headers.get("authorization") or ""
            pad = "x" * (SERVER_ERROR_BODY_CHARS - len("debug: ") - len(auth) + 8)
            return httpx.Response(500, text=f"debug: {pad}{auth} tail")
        if mode == "zero-width":
            token = (request.headers.get("authorization") or "").removeprefix("Bearer ")
            split = token[:5] + "\u200b" + token[5:]
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"token={split}"}]}})
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


async def _call(
    spec: TargetSpec, mode: str, credentials: dict[str, str], extra: dict | None = None
) -> str:
    target = HttpTarget(spec, http_client=_echoing_upstream(mode))
    await target.startup()
    try:
        ctx = Context(identity="p", agent_name="p", credentials=credentials, extra=extra or {})
        result = await target.dispatch("echo", {}, ctx)
    finally:
        await target.shutdown()
    return json.dumps(result.content, ensure_ascii=False) + (result.error or "")


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
    """Only the credential is masked: the rest of the echoed headers, here the
    exact correlation id, comes back as it was."""
    seen = await _call(_spec(), "result", {"K": TOKEN}, {CORRELATION_ID_KEY: "corr-7f3a9e1b-pass"})
    assert "corr-7f3a9e1b-pass" in seen
    assert seen.count(MASK) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("trust", ["trusted", "untrusted"])
async def test_a_credential_cut_by_the_5xx_truncation_leaks_no_prefix(trust: str) -> None:
    """Prudence round 1: the body was cut to 200 characters before masking, so a
    token straddling the cut came back as an unmasked prefix."""
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    seen = await _call(_spec(trust=trust), "http-500-straddle", {"K": token})
    for n in range(8, len(token) + 1):
        assert token[:n] not in seen, n
    assert MASK in seen


@pytest.mark.asyncio
async def test_a_hidden_code_point_inside_the_token_does_not_defeat_the_mask() -> None:
    """Prudence round 1: on an untrusted target the sanitiser strips U+200B
    after masking, which rejoined a split token. It is masked again after."""
    seen = await _call(_spec(trust="untrusted"), "zero-width", {"K": TOKEN})
    assert TOKEN not in seen and MASK in seen


@pytest.mark.asyncio
async def test_catalog_headers_and_basic_static_bearer_never_come_back(monkeypatch) -> None:
    monkeypatch.setenv("CAT_HEADER_ENV", "catalog-header-secret-31")
    seen = await _call(_spec(catalog_headers_env={"X-Cat": "CAT_HEADER_ENV"}), "result", {"K": TOKEN})
    assert "x-cat" in seen.lower(), "the catalog header must ride the call for this to test it"
    assert "catalog-header-secret-31" not in seen and TOKEN not in seen

    seen = await _call(
        _spec(auth_method="bearer", auth_scheme="basic", credential_key=None,
              bearer_token="svc@example.com:static-basic-secret-42"),
        "result", {},
    )
    assert "static-basic-secret-42" not in seen
    assert base64.b64encode(b"svc@example.com:static-basic-secret-42").decode() not in seen


@pytest.mark.asyncio
async def test_per_persona_session_path_is_masked() -> None:
    seen = await _call(_spec(session="per-persona"), "result", {"K": TOKEN})
    assert TOKEN not in seen and MASK in seen


@pytest.mark.asyncio
async def test_the_catalog_token_is_among_the_call_secrets() -> None:
    target = HttpTarget(_spec(), http_client=_echoing_upstream("result"))
    target._catalog_token = "minted-catalog-token-55"
    secrets = target._call_secrets(Context(identity="p", agent_name="p", credentials={}))
    assert "minted-catalog-token-55" in secrets


def test_more_encodings_are_covered() -> None:
    forms = with_encodings(["a/b+c=d&e/1234"])
    assert "a%2fb%2bc%3dd%26e%2f1234" in forms
    assert "a\\/b+c=d&e\\/1234" in forms
    assert b"a/b+c=d&e/1234".hex() in forms and b"a/b+c=d&e/1234".hex().upper() in forms


def test_keys_that_mask_alike_are_both_kept() -> None:
    b64 = base64.b64encode(TOKEN.encode()).decode()
    masked, hits = mask_content({TOKEN: 1, b64: 2}, with_encodings([TOKEN]))
    assert hits == 2
    assert sorted(masked.values()) == [1, 2]
    assert set(masked) == {MASK, f"{MASK}#2"}
