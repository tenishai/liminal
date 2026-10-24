"""POST /mcp refuses browser-shaped requests (liminal#190).

The attack: a page in the operator's browser POSTs a text/plain body (no CORS
preflight) to a loopback liminal running with LIMINAL_AUTH_DISABLED=1, or
rebinds its own domain to 127.0.0.1 and posts as same-origin. Both carry an
Origin the server can check, and the first carries a Content-Type no real MCP
client sends.
"""

from __future__ import annotations

import json

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from liminal.server import create_app

LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
SET = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "scratchpad.set", "arguments": {"key": "k", "value": "pwned"}},
}
GET = {
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {"name": "scratchpad.get", "arguments": {"key": "k"}},
}
JSON_CT = {"Content-Type": "application/json"}


@pytest_asyncio.fixture
async def open_client(monkeypatch, registry):
    """An auth-off app: the deployment the attack targets."""
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    monkeypatch.delenv("LIMINAL_ALLOWED_ORIGINS", raising=False)
    app = create_app(registry=registry)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _post(c, envelope, headers):
    return await c.post("/mcp", content=json.dumps(envelope), headers=headers)


@pytest.mark.asyncio
async def test_no_cors_text_plain_call_from_hostile_origin_does_not_run(open_client) -> None:
    r = await _post(
        open_client, SET,
        {"Origin": "https://evil.example", "Content-Type": "text/plain"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["message"] == "origin not allowed"
    # The write did not happen.
    r = await _post(open_client, GET, JSON_CT)
    assert "pwned" not in r.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "null",  # sandboxed iframe or file: page
        "http://localhost.evil.example",
        "http://127.0.0.1.evil.example",
        "http://localhost:notaport",
        "ftp://localhost",
    ],
)
async def test_non_loopback_origin_refused_even_with_json(open_client, origin) -> None:
    # The DNS-rebinding case: same-origin to the browser, so the page can send
    # application/json. The Origin header is what gives it away.
    r = await _post(open_client, LIST, {"Origin": origin, **JSON_CT})
    assert r.status_code == 403
    assert "result" not in r.json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:6274",
        "http://127.0.0.1",
        "https://[::1]:8443",
        "HTTP://LOCALHOST:9100/",
    ],
)
async def test_loopback_origin_allowed(open_client, origin) -> None:
    r = await _post(open_client, LIST, {"Origin": origin, **JSON_CT})
    assert r.status_code == 200
    assert "result" in r.json()


@pytest.mark.asyncio
async def test_listed_origin_allowed(monkeypatch, registry) -> None:
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    monkeypatch.setenv("LIMINAL_ALLOWED_ORIGINS", " https://ui.example:8443/ , https://b.example")
    app = create_app(registry=registry)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await _post(c, LIST, {"Origin": "https://ui.example:8443", **JSON_CT})
        assert r.status_code == 200
        r = await _post(c, LIST, {"Origin": "https://ui.example", **JSON_CT})
        assert r.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/plain"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"Content-Type": "multipart/form-data; boundary=x"},
        {},  # an untyped Blob body sends no Content-Type
    ],
)
async def test_non_json_content_type_refused(open_client, headers) -> None:
    r = await _post(open_client, SET, headers)
    assert r.status_code == 415
    assert "result" not in r.json()


@pytest.mark.asyncio
async def test_json_with_charset_and_no_origin_allowed(open_client) -> None:
    r = await _post(open_client, LIST, {"Content-Type": "Application/JSON; charset=utf-8"})
    assert r.status_code == 200
    assert "result" in r.json()


@pytest.mark.asyncio
async def test_guard_runs_with_auth_on(client) -> None:
    # The spec's MUST is unconditional; the auth-on app refuses the same way.
    r = await _post(client, LIST, {"Origin": "https://evil.example", **JSON_CT})
    assert r.status_code == 403
