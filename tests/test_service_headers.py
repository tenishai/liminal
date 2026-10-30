"""auth_method="service-headers" + catalog_headers_env: upstreams that want the
calling persona's credentials as named headers (a key pair, not Authorization),
and a shared credential for the catalog fetch alone.

Datadog's hosted MCP server is the first: every request carries `DD_API_KEY` and
`DD_APPLICATION_KEY`, the application key is leased per agent by the permission
service, and `initialize`/`tools/list` (which no agent makes) use the gateway's
own key from its env. The rule under test is the one service-token already
keeps (liminal#80): a persona's call carries its own credentials or does not go
out; and the catalog's shared headers never ride a persona's call.
"""

from __future__ import annotations

import json

import pytest

from liminal.protocol import Context
from liminal.target import HttpTarget, TargetConfigError, TargetSpec, load_target_specs

from .test_http_target import _client, _http_spec, _responder

DD = {"DD_API_KEY": "DD_API_KEY", "DD_APPLICATION_KEY": "DD_APP_KEY"}


def _calls(captured: list[dict], method: str) -> list[dict]:
    return [c for c in captured if json.loads(c["body"]).get("method") == method]


# ---- dispatch -------------------------------------------------------------


@pytest.mark.asyncio
async def test_each_credential_rides_its_named_header_and_nothing_on_authorization() -> None:
    captured: list[dict] = []
    target = HttpTarget(
        _http_spec(auth_method="service-headers", credential_headers=DD),
        http_client=_client(_responder(), captured=captured),
    )
    await target.startup()
    try:
        ctx = Context(identity="sherlock", agent_name="sherlock",
                      credentials={"DD_API_KEY": "api-1", "DD_APP_KEY": "app-1", "DD_SITE": "us3"})
        result = await target.dispatch("search", {}, ctx)
        assert result.is_error is False
        call = _calls(captured, "tools/call")[0]["headers"]
        assert call["dd_api_key"] == "api-1" and call["dd_application_key"] == "app-1"
        assert "authorization" not in call and "dd_site" not in call
    finally:
        await target.shutdown()


@pytest.mark.asyncio
async def test_a_missing_or_blank_credential_refuses_before_any_request_leaves() -> None:
    captured: list[dict] = []
    target = HttpTarget(
        _http_spec(auth_method="service-headers", credential_headers=DD),
        http_client=_client(_responder(), captured=captured),
    )
    await target.startup()
    try:
        for creds in ({"DD_API_KEY": "api-1"}, {"DD_API_KEY": "api-1", "DD_APP_KEY": "   "}):
            result = await target.dispatch("search", {}, Context(identity="x", agent_name="x", credentials=creds))
            assert result.is_error is True
            assert "DD_APP_KEY" in result.error and "unauthenticated" in result.error
        assert _calls(captured, "tools/call") == []
    finally:
        await target.shutdown()


@pytest.mark.asyncio
async def test_catalog_headers_ride_the_catalog_fetch_only_never_a_personas_call(monkeypatch) -> None:
    monkeypatch.setenv("SHARED_API", "shared-api")
    monkeypatch.setenv("SHARED_APP", "shared-app")
    captured: list[dict] = []
    target = HttpTarget(
        _http_spec(
            auth_method="service-headers", credential_headers=DD, session="per-persona",
            catalog_headers_env={"DD_API_KEY": "SHARED_API", "DD_APPLICATION_KEY": "SHARED_APP"},
        ),
        http_client=_client(_responder(), captured=captured),
    )
    await target.startup()
    try:
        catalog_init, = _calls(captured, "initialize")
        listing, = _calls(captured, "tools/list")
        for req in (catalog_init, listing):
            assert req["headers"]["dd_api_key"] == "shared-api"
            assert req["headers"]["dd_application_key"] == "shared-app"
        assert len(await target.list_tools()) == 2

        ctx = Context(identity="sherlock", agent_name="sherlock", issuer="iss",
                      credentials={"DD_API_KEY": "api-s", "DD_APP_KEY": "app-s"})
        assert (await target.dispatch("search", {}, ctx)).is_error is False
        # The persona's session was opened with the persona's own key pair, and
        # the call carried it too; the shared pair is on neither.
        session_init = _calls(captured, "initialize")[1]["headers"]
        call = _calls(captured, "tools/call")[0]["headers"]
        for h in (session_init, call):
            assert h["dd_api_key"] == "api-s" and h["dd_application_key"] == "app-s"
            assert "shared" not in json.dumps(h)
    finally:
        await target.shutdown()


@pytest.mark.asyncio
async def test_an_unset_catalog_variable_fails_startup_naming_it(monkeypatch) -> None:
    monkeypatch.delenv("MISSING_SHARED_KEY", raising=False)
    target = HttpTarget(
        _http_spec(auth_method="service-headers", credential_headers=DD,
                   catalog_headers_env={"DD_API_KEY": "MISSING_SHARED_KEY"}),
        http_client=_client(_responder()),
    )
    with pytest.raises(RuntimeError, match=r"catalog_headers_env\['DD_API_KEY'\] \$MISSING_SHARED_KEY"):
        await target.startup()


# ---- config ---------------------------------------------------------------


def _spec(**over) -> TargetSpec:
    base = dict(name="dd", address="https://mcp.example/v1", auth_method="service-headers", credential_headers=dict(DD))
    base.update(over)
    return TargetSpec(**base)


def test_the_toml_shape_loads() -> None:
    [spec] = load_target_specs([{
        "name": "datadog-mcp", "transport": "http", "address": "https://mcp.us3.example/v1",
        "auth_method": "service-headers", "session": "per-persona", "required_scope": "datadog:read",
        "credential_headers": dict(DD),
        "catalog_headers_env": {"DD_API_KEY": "DD_API_KEY", "DD_APPLICATION_KEY": "DD_APP_KEY"},
    }])
    assert spec.credential_headers == DD and spec.catalog_headers_env["DD_APPLICATION_KEY"] == "DD_APP_KEY"


@pytest.mark.parametrize("over, match", [
    ({"credential_headers": {}}, "non-empty \\[target.credential_headers\\]"),
    ({"auth_method": "service-token", "credential_key": "K"}, "read only for auth_method='service-headers'"),
    ({"credential_headers": {"Authorization": "TOKEN"}}, "may not set 'Authorization'"),
    ({"credential_headers": {"X-Key": "A", "x-key": "B"}}, "same header"),
    ({"credential_headers": {"X Key": "A"}}, "not a valid HTTP field name"),
    ({"credential_headers": {"X-Key": ""}}, "non-empty string"),
    ({"headers": {"DD_API_KEY": "static"}}, "repeats a static headers name"),
    ({"catalog_headers_env": {"DD_API_KEY": "not a name"}}, "must name an environment variable"),
    ({"auth_method": "bearer", "bearer_token": "t", "credential_headers": {},
      "catalog_headers_env": {"X": "Y"}}, "catalog_headers_env applies to"),
])
def test_refused_at_load(over, match) -> None:
    with pytest.raises(TargetConfigError, match=match):
        _spec(**over).validate()


def test_stdio_refuses_service_headers() -> None:
    with pytest.raises(TargetConfigError, match="stdio targets cannot use auth_method='service-headers'"):
        TargetSpec(name="s", transport="stdio", command=("x",), auth_method="service-headers",
                   credential_headers=dict(DD)).validate()
