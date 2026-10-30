"""Live targets (liminal#222): federated HTTP targets added, replaced and removed
through the admin plane while serving, persisted in the policy database, with
the file's targets and the handlers keeping their names.

Same stance as test_policy_inversion: a sovereign app over HTTP, a parent token
for the admin plane, a third-party token for the data plane; the upstream is the
mock MCP server test_http_target uses.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from joserfc.jwk import KeySet

from liminal.handlers.scratchpad import ScratchpadHandler
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import (
    LiveTargets,
    LiveTargetStore,
    MultiIssuerJWKSVerifier,
    SqlitePolicyStore,
    StaticKeySetVerifier,
    create_admin_app,
    create_app,
)
from liminal.server.live_targets import FileOwned, LiveTargetError
from liminal.server.mcp_types import ERROR_UNAUTHORIZED
from liminal.target import TargetSpec

from .test_http_target import _client, _responder
from .test_policy_inversion import SVC, _hdr, _key, _mint, _rpc

SPEC = {"transport": "http", "address": "http://upstream.test", "trust": "trusted", "refresh_tools_interval_seconds": 0}


def _verifier(kp, ks):
    return MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(key_set=KeySet([kp]), expected_issuer="rd-cabal", expected_audience=SVC),
            "shaz-cabal": StaticKeySetVerifier(key_set=KeySet([ks]), expected_issuer="shaz-cabal", expected_audience=SVC),
        },
        parents=frozenset({"rd-cabal"}),
    )


def _build(tmp_path, *, file_targets=(), live=None):
    """A sovereign data-plane app with the admin routes mounted, its policy store,
    and the live-target controller (a fresh one over the same database unless given)."""
    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "policy.db"), parent_issuer="rd-cabal")
    live = live or LiveTargets(LiveTargetStore(str(tmp_path / "policy.db")), http_client_factory=lambda: _client(_responder()))
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    app = create_app(jwt_verifier=_verifier(kp, ks), registry=reg, policy_store=store, targets=list(file_targets), live_targets=live)
    return app, store, live, kp, ks


@pytest_asyncio.fixture
async def sov(tmp_path):
    app, store, live, kp, ks = _build(tmp_path)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            yield client, store, live, kp, ks
    store.close()


async def _grant(store, scopes=("dd:read",)):
    await store.grant("shaz-cabal", "rook", scopes=set(scopes), allowed_handlers=None)


# ---- the lane -------------------------------------------------------------


@pytest.mark.asyncio
async def test_put_serves_the_target_at_once_and_lists_it(sov) -> None:
    client, store, _live, kp, ks = sov
    ptok = _mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")
    r = await client.put("/admin/targets/dd", json=SPEC, headers=_hdr(ptok))
    assert r.status_code == 200 and r.json() == {"name": "dd", "status": "ready"}, r.text
    await _grant(store)
    tok = _mint(ks, iss="shaz-cabal")
    tools = (await _rpc(client, tok, "tools/list")).json()["result"]["tools"]
    assert {t["name"] for t in tools} >= {"dd.search", "dd.ping"}, tools
    hit = (await _rpc(client, tok, "tools/call", {"name": "dd.search", "arguments": {}})).json()
    assert "error" not in hit and hit["result"]["content"][0]["text"] == "hit", hit
    listed = (await client.get("/admin/targets", headers=_hdr(ptok))).json()["targets"]
    assert {"name": "dd", "source": "live", "status": "ready", "spec": SPEC} in listed, listed
    health = (await client.get("/healthz")).json()
    assert health["targets"]["dd"] == "ready" and health["status"] == "ok"


@pytest.mark.asyncio
async def test_delete_takes_the_tools_away_and_a_second_delete_is_404(sov) -> None:
    client, store, _live, kp, ks = sov
    ptok = _mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")
    await client.put("/admin/targets/dd", json=SPEC, headers=_hdr(ptok))
    await _grant(store)
    tok = _mint(ks, iss="shaz-cabal")
    r = await client.delete("/admin/targets/dd", headers=_hdr(ptok))
    assert r.status_code == 200 and r.json() == {"removed": "dd"}
    tools = (await _rpc(client, tok, "tools/list")).json()["result"]["tools"]
    assert not any(t["name"].startswith("dd.") for t in tools)
    assert "dd" not in (await client.get("/healthz")).json()["targets"]
    assert (await client.delete("/admin/targets/dd", headers=_hdr(ptok))).status_code == 404


@pytest.mark.asyncio
async def test_a_replacement_takes_the_name_and_the_old_one_is_shut_down(sov) -> None:
    client, _store, live, kp, _ks = sov
    ptok = _mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")
    await client.put("/admin/targets/dd", json=SPEC, headers=_hdr(ptok))
    first = live._dispatcher.targets["dd"]
    r = await client.put("/admin/targets/dd", json={**SPEC, "required_scope": "dd:read"}, headers=_hdr(ptok))
    assert r.status_code == 200
    second = live._dispatcher.targets["dd"]
    assert second is not first and first._client is None, "the replaced target was shut down"
    assert live.scope_for("dd.search") == "dd:read"


@pytest.mark.asyncio
async def test_live_scope_rules_are_enforced_like_a_file_targets(sov) -> None:
    client, store, _live, kp, ks = sov
    ptok = _mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")
    await client.put("/admin/targets/dd", json={**SPEC, "required_scope": "dd:read"}, headers=_hdr(ptok))
    await _grant(store, scopes=("other:read",))
    tok = _mint(ks, iss="shaz-cabal")
    denied = (await _rpc(client, tok, "tools/call", {"name": "dd.search", "arguments": {}})).json()
    assert denied["error"]["code"] == ERROR_UNAUTHORIZED and "dd:read" in denied["error"]["message"], denied
    await _grant(store, scopes=("dd:read",))
    ok = (await _rpc(client, tok, "tools/call", {"name": "dd.search", "arguments": {}})).json()
    assert "error" not in ok, ok


# ---- refusals ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_refusals_at_the_api(sov) -> None:
    client, _store, _live, kp, ks = sov
    ptok = _mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")
    # a handler's name is not for the taking
    r = await client.put("/admin/targets/scratchpad", json=SPEC, headers=_hdr(ptok))
    assert r.status_code == 409 and "configuration" in r.json()["detail"]
    assert (await client.delete("/admin/targets/scratchpad", headers=_hdr(ptok))).status_code == 409
    # no secret travels in a spec
    r = await client.put("/admin/targets/dd", json={**SPEC, "auth_method": "bearer", "bearer_token": "s3cret"}, headers=_hdr(ptok))
    assert r.status_code == 422 and "env variable names" in r.json()["detail"] and "s3cret" not in r.text
    # an invalid spec is the loader's sentence, not a traceback
    r = await client.put("/admin/targets/dd", json={**SPEC, "auth_method": "service-headers"}, headers=_hdr(ptok))
    assert r.status_code == 422 and "credential_headers" in r.json()["detail"]
    # stdio is not served live
    r = await client.put("/admin/targets/dd", json={"transport": "stdio", "command": ["x"]}, headers=_hdr(ptok))
    assert r.status_code == 422 and "http" in r.json()["detail"]
    # the body may not rename the path
    r = await client.put("/admin/targets/dd", json={**SPEC, "name": "other"}, headers=_hdr(ptok))
    assert r.status_code == 422
    # only a parent admin reaches the lane
    tok = _mint(ks, iss="shaz-cabal")
    assert (await client.put("/admin/targets/dd", json=SPEC, headers=_hdr(tok))).status_code == 403
    assert (await client.get("/admin/targets", headers=_hdr(tok))).status_code == 403
    assert (await client.get("/admin/targets")).status_code == 401


@pytest.mark.asyncio
async def test_a_file_target_keeps_its_name(tmp_path) -> None:
    file_spec = TargetSpec(name="vendor", address="http://file.test", trust="trusted", refresh_tools_interval_seconds=0)
    app, store, live, kp, _ks = _build(tmp_path, file_targets=[file_spec])
    # the file target's upstream is the same mock; startup is best effort here
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            ptok = _mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")
            r = await client.put("/admin/targets/vendor", json=SPEC, headers=_hdr(ptok))
            assert r.status_code == 409 and "targets.toml" in r.json()["detail"]
            listed = (await client.get("/admin/targets", headers=_hdr(ptok))).json()["targets"]
            assert any(t["name"] == "vendor" and t["source"] == "file" for t in listed), listed
    store.close()


# ---- persistence --------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_live_target_comes_back_at_the_next_boot_unless_the_file_took_its_name(tmp_path) -> None:
    app, store, _live, kp, ks = _build(tmp_path)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            ptok = _mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")
            assert (await client.put("/admin/targets/dd", json=SPEC, headers=_hdr(ptok))).status_code == 200
            await client.put("/admin/targets/shadow", json=SPEC, headers=_hdr(ptok))
    store.close()
    # Second boot: a fresh controller over the same database, and the file now holds "shadow".
    live2 = LiveTargets(LiveTargetStore(str(tmp_path / "policy.db")), http_client_factory=lambda: _client(_responder()))
    file_spec = TargetSpec(name="shadow", address="http://file.test", trust="trusted", refresh_tools_interval_seconds=0)
    app2, store2, _live2, kp2, _ks2 = _build(tmp_path, file_targets=[file_spec], live=live2)
    async with app2.router.lifespan_context(app2):
        async with AsyncClient(transport=ASGITransport(app=app2), base_url="http://test") as client:
            ptok = _mint(kp2, iss="rd-cabal", persona="ops", sub="ops-1")
            listed = {t["name"]: t for t in (await client.get("/admin/targets", headers=_hdr(ptok))).json()["targets"]}
            assert listed["dd"]["source"] == "live" and listed["dd"]["status"] == "ready", listed
            assert listed["shadow"]["source"] == "file", "the file's target won; the stored row was left alone"
            assert (await client.get("/healthz")).json()["targets"]["dd"] == "ready"
    store2.close()


# ---- the admin app on its own listener shares the controller --------------------


@pytest.mark.asyncio
async def test_the_admin_listener_applies_to_the_data_planes_multiplexer(tmp_path) -> None:
    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "policy.db"), parent_issuer="rd-cabal")
    live = LiveTargets(LiveTargetStore(str(tmp_path / "policy.db")), http_client_factory=lambda: _client(_responder()))
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    verifier = _verifier(kp, ks)
    data = create_app(jwt_verifier=verifier, registry=reg, policy_store=store, live_targets=live, mount_admin=False)
    admin = create_admin_app(jwt_verifier=verifier, policy_store=store, live_targets=live)
    async with data.router.lifespan_context(data):
        async with AsyncClient(transport=ASGITransport(app=admin), base_url="http://admin") as a, \
                   AsyncClient(transport=ASGITransport(app=data), base_url="http://data") as d:
            ptok = _mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")
            assert (await d.put("/admin/targets/dd", json=SPEC, headers=_hdr(ptok))).status_code == 404, "no admin routes on the data plane"
            assert (await a.put("/admin/targets/dd", json=SPEC, headers=_hdr(ptok))).status_code == 200
            await _grant(store)
            tok = _mint(ks, iss="shaz-cabal")
            tools = (await _rpc(d, tok, "tools/list")).json()["result"]["tools"]
            assert any(t["name"] == "dd.search" for t in tools), tools
    store.close()


# ---- the controller alone -------------------------------------------------------


def test_spec_for_refuses_before_anything_runs() -> None:
    live = LiveTargets(LiveTargetStore(":memory:"))
    with pytest.raises(LiveTargetError, match="env variable names"):
        live.spec_for("x", {**SPEC, "auth_method": "bearer", "bearer_token": "s"})
    with pytest.raises(LiveTargetError, match="not attached"):
        import asyncio
        asyncio.run(live.put("x", SPEC))
    assert FileOwned.__mro__[1] is LiveTargetError
