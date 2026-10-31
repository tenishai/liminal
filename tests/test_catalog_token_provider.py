"""catalog_token_provider: a bearer for the catalog fetch, minted on demand.

GitHub's hosted MCP server refuses an unauthenticated ``initialize``, and
wants the credential on ``Authorization``, which ``catalog_headers_env`` may
not set. A deployment registers a provider under ``liminal.catalog_tokens``
(the gateway mints an installation token from its own GitHub App) and the
target names it. The rules under test: the provider is awaited before every
catalog fetch, its token rides the catalog client's requests alone, a persona's
session and calls carry the persona's own credential, and a provider liminal
cannot load or that mints nothing fails the target's startup naming it.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from liminal.protocol import Context
from liminal.target import HttpTarget, TargetConfigError, catalog_tokens

from .test_http_target import _client, _http_spec, _responder


def _calls(captured: list[dict], method: str) -> list[dict]:
    return [c for c in captured if json.loads(c["body"]).get("method") == method]


class _Minter:
    """A provider that mints a new token each time it is awaited."""

    def __init__(self, prefix: str = "minted") -> None:
        self.prefix, self.calls = prefix, 0

    async def __call__(self) -> str:
        self.calls += 1
        return f"{self.prefix}-{self.calls}"


def _register(monkeypatch, **providers) -> None:
    """Fake the entry-point group: name -> factory returning the provider."""
    eps = [SimpleNamespace(name=name, load=lambda p=p: (lambda: p)) for name, p in providers.items()]
    monkeypatch.setattr(catalog_tokens, "entry_points", lambda group: eps if group == catalog_tokens.ENTRY_POINT_GROUP else [])


def _github_like(**over):
    base = dict(auth_method="service-token", credential_key="GITHUB_TOKEN", session="per-persona",
                headers={"X-MCP-Readonly": "true"}, catalog_token_provider="github-app")
    base.update(over)
    return _http_spec(**base)


async def test_minted_token_rides_the_catalog_fetch_only_never_a_personas_call(monkeypatch) -> None:
    minter = _Minter()
    _register(monkeypatch, **{"github-app": minter})
    captured: list[dict] = []
    target = HttpTarget(_github_like(), http_client=_client(_responder(), captured=captured))
    await target.startup()
    try:
        assert minter.calls == 1
        catalog_init, = _calls(captured, "initialize")
        listing, = _calls(captured, "tools/list")
        for req in (catalog_init, listing):
            assert req["headers"]["authorization"] == "Bearer minted-1"
            assert req["headers"]["x-mcp-readonly"] == "true"
        assert len(await target.list_tools()) == 2

        ctx = Context(identity="sherlock", agent_name="sherlock", issuer="iss",
                      credentials={"GITHUB_TOKEN": "ghs_persona"})
        assert (await target.dispatch("search", {}, ctx)).is_error is False
        session_init = _calls(captured, "initialize")[1]["headers"]
        call = _calls(captured, "tools/call")[0]["headers"]
        for h in (session_init, call):
            assert h["authorization"] == "Bearer ghs_persona"
            assert "minted" not in json.dumps(h)
        # A persona without a credential is refused, never sent with the catalog's token.
        bare = Context(identity="janus", agent_name="janus", issuer="iss", credentials={})
        refused = await target.dispatch("search", {}, bare)
        assert refused.is_error is True and len(_calls(captured, "tools/call")) == 1
    finally:
        await target.shutdown()


async def test_each_refresh_mints_a_fresh_token(monkeypatch) -> None:
    minter = _Minter()
    _register(monkeypatch, **{"github-app": minter})
    captured: list[dict] = []
    target = HttpTarget(_github_like(), http_client=_client(_responder(), captured=captured))
    await target.startup()
    try:
        await target._refresh_tools_once()
        await target._refresh_tools_once()
        assert minter.calls == 3
        listings = [c["headers"]["authorization"] for c in _calls(captured, "tools/list")]
        assert listings == ["Bearer minted-1", "Bearer minted-2", "Bearer minted-3"]
        assert target.catalog_status == "ready"
    finally:
        await target.shutdown()


async def test_a_mint_that_fails_on_refresh_is_a_failed_refresh_not_a_crash(monkeypatch) -> None:
    class Flaky(_Minter):
        async def __call__(self) -> str:
            if self.calls:
                raise RuntimeError("app key rejected")
            return await super().__call__()
    _register(monkeypatch, **{"github-app": Flaky()})
    target = HttpTarget(_github_like(), http_client=_client(_responder()))
    await target.startup()
    try:
        assert target.catalog_status == "ready"
        await target._refresh_tools_once()
        assert target.catalog_status == "catalog fetch failed (refresh)"
        assert len(await target.list_tools()) == 2  # the last good catalog still serves
    finally:
        await target.shutdown()


async def test_an_unknown_provider_fails_startup_naming_it(monkeypatch) -> None:
    _register(monkeypatch, **{"something-else": _Minter()})
    target = HttpTarget(_github_like(), http_client=_client(_responder()))
    with pytest.raises(catalog_tokens.CatalogTokenProviderError, match=r"'github-app' is not registered .* \(known: something-else\)"):
        await target.startup()


async def test_an_empty_token_fails_startup_naming_the_provider(monkeypatch) -> None:
    async def blank() -> str:
        return "   "
    _register(monkeypatch, **{"github-app": blank})
    captured: list[dict] = []
    target = HttpTarget(_github_like(), http_client=_client(_responder(), captured=captured))
    with pytest.raises(RuntimeError, match=r"catalog_token_provider 'github-app' returned an empty token"):
        await target.startup()
    assert captured == []  # nothing left unauthenticated


def test_load_refuses_a_provider_that_is_not_callable(monkeypatch) -> None:
    _register(monkeypatch, **{"github-app": "not a callable"})
    with pytest.raises(catalog_tokens.CatalogTokenProviderError, match="must be an async callable"):
        catalog_tokens.load_catalog_token_provider("github-app")


@pytest.mark.parametrize("over, match", [
    (dict(auth_method="bearer", bearer_token="t", credential_key=None), "catalog_token_provider applies to"),
    (dict(auth_method="none", credential_key=None), "catalog_token_provider applies to"),
    (dict(catalog_token_provider="  "), "must be a provider name"),
    (dict(catalog_token_provider=3), "must be a provider name"),
])
def test_refused_at_load(over, match) -> None:
    with pytest.raises(TargetConfigError, match=match):
        _github_like(**over).validate()


def test_authorization_in_catalog_headers_is_still_refused() -> None:
    # The provider is the one way a catalog bearer is given; the header table stays closed.
    with pytest.raises(TargetConfigError, match="may not set 'Authorization'"):
        _http_spec(auth_method="service-token", credential_key="K",
                   catalog_headers_env={"Authorization": "SOME_ENV"}).validate()
