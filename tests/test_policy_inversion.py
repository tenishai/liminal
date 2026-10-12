"""Authorization inversion + federation admin — federation Part 2 (liminal#20).

Exercises the sovereign path end-to-end over HTTP: a multi-issuer verifier + a
SqlitePolicyStore, proving the server-side grant — not the caller's token — is
authoritative, and that the admin surface is parent-gated.
"""

from __future__ import annotations

import time

import pytest
import pytest_asyncio
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from liminal.dispatch import Multiplexer
from liminal.handlers.scratchpad import ScratchpadHandler
from liminal.protocol import Context, ToolResult, ToolSpec
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import (
    MultiIssuerJWKSVerifier,
    SqlitePolicyStore,
    StaticKeySetVerifier,
    create_app,
)
from liminal.server.mcp_types import ERROR_UNKNOWN_TOOL
from liminal.target.base import TrustTier
from liminal.target.inprocess import InProcessTarget

SVC = "archivist@rd"


class _EchoExtraHandler:
    """Test handler that returns ctx.extra, so a test can assert exactly what
    sandbox config the route passed the handler."""

    def tools(self) -> list[ToolSpec]:
        return [
            ToolSpec(name="peek", description="echo ctx.extra", input_schema={"type": "object", "properties": {}})
        ]

    def capability_card(self) -> dict:
        return {
            "handler": "echo",
            "description": "echoes ctx.extra for tests",
            "tools": [{"name": "peek", "description": "echo ctx.extra"}],
            "activation": "always",
            "credential_keys": [],
            "labels": {"tier": "test"},
        }

    async def dispatch(self, name: str, payload: dict, ctx: Context) -> ToolResult:
        return ToolResult.json({"extra": ctx.extra})


def _verifier(kp: RSAKey, ks: RSAKey) -> MultiIssuerJWKSVerifier:
    return MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=KeySet([kp]), expected_issuer="rd-cabal", expected_audience=SVC
            ),
            "shaz-cabal": StaticKeySetVerifier(
                key_set=KeySet([ks]), expected_issuer="shaz-cabal", expected_audience=SVC
            ),
        },
        parents=frozenset({"rd-cabal"}),
    )


def _key() -> RSAKey:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    k = RSAKey.import_key(pem)
    k.ensure_kid()
    return k


def _mint(key: RSAKey, *, iss: str, persona="rook", sub="rook-primus", aud=SVC, ttl=60, **extra) -> str:
    now = int(time.time())
    payload = {
        "iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl,
        "cabal_persona": persona,
    }
    payload.update(extra)
    return jwt.encode({"alg": "RS256", "kid": key.kid, "typ": "JWT"}, payload, key)


def _hdr(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


async def _rpc(client, tok, method, params=None):
    return await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers=_hdr(tok),
    )


@pytest_asyncio.fixture
async def sov(tmp_path):
    kp, ks = _key(), _key()  # parent (rd-cabal), third-party (shaz-cabal)
    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(
                key_set=KeySet([kp]), expected_issuer="rd-cabal", expected_audience=SVC
            ),
            "shaz-cabal": StaticKeySetVerifier(
                key_set=KeySet([ks]), expected_issuer="shaz-cabal", expected_audience=SVC
            ),
        },
        parents=frozenset({"rd-cabal"}),
    )
    store = SqlitePolicyStore(str(tmp_path / "policy.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    app = create_app(jwt_verifier=verifier, registry=reg, policy_store=store)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, kp, ks, store
    store.close()


# ---- the inversion --------------------------------------------------------


@pytest.mark.asyncio
async def test_no_grant_denied(sov) -> None:
    client, _kp, ks, _store = sov
    tok = _mint(ks, iss="shaz-cabal")  # shaz, no grant yet
    body = (await _rpc(client, tok, "tools/list")).json()
    assert body.get("error"), body
    assert "no policy grant" in body["error"]["message"]


@pytest.mark.asyncio
async def test_no_grant_denial_is_logged(sov) -> None:
    """liminal#166: a denied caller gets one warning naming issuer, persona,
    agent and reason, and the token appears in no field."""
    client, _kp, ks, _store = sov
    tok = _mint(ks, iss="shaz-cabal")
    with structlog.testing.capture_logs() as logs:
        await _rpc(client, tok, "tools/list")
    denied = [e for e in logs if e["event"] == "access.denied"]
    assert len(denied) == 1, logs
    entry = denied[0]
    assert entry["log_level"] == "warning"
    assert entry["issuer"] == "shaz-cabal"
    assert entry["persona"] == "rook"
    assert entry["reason"] == "no grant"
    assert "agent" in entry
    assert all(tok not in str(v) for v in entry.values())


@pytest.mark.asyncio
async def test_granted_caller_logs_no_denial(sov) -> None:
    client, _kp, ks, store = sov
    await store.grant("shaz-cabal", "rook", scopes={"mem:query"}, allowed_handlers=None)
    tok = _mint(ks, iss="shaz-cabal")
    with structlog.testing.capture_logs() as logs:
        await _rpc(client, tok, "tools/list")
    assert not [e for e in logs if e["event"] == "access.denied"], logs


@pytest.mark.asyncio
async def test_token_cannot_selfgrant(sov) -> None:
    """Core proof: a foreign token's generous tool_extras is ignored; the
    server-side grant is authoritative."""
    client, _kp, ks, store = sov
    # Server grants shaz/rook NO handlers (empty = deny all)...
    await store.grant("shaz-cabal", "rook", scopes={"mem:query"}, allowed_handlers=set())
    # ...but shaz mints a token claiming it can use scratchpad.
    tok = _mint(
        ks, iss="shaz-cabal",
        tool_extras={"liminal.allowed_handlers": ["scratchpad"]},
        cabal_scope=["dispatch"],
    )
    # tools/list: scratchpad hidden despite the token claim.
    tools = (await _rpc(client, tok, "tools/list")).json()["result"]["tools"]
    assert all(not t["name"].startswith("scratchpad") for t in tools), tools
    # tools/call: denied by the server grant, not the token.
    err = (
        await _rpc(client, tok, "tools/call", {"name": "scratchpad.write", "arguments": {}})
    ).json()["error"]
    assert err["message"].startswith("handler 'scratchpad' not in")


@pytest.mark.asyncio
async def test_grant_makes_handler_visible(sov) -> None:
    client, _kp, ks, store = sov
    await store.grant("shaz-cabal", "rook", scopes={"mem:query"}, allowed_handlers=None)  # all
    tok = _mint(ks, iss="shaz-cabal")
    tools = (await _rpc(client, tok, "tools/list")).json()["result"]["tools"]
    assert any(t["name"].startswith("scratchpad") for t in tools), tools


# ---- admin surface (parent guardian plane) --------------------------------


@pytest.mark.asyncio
async def test_admin_grant_by_parent(sov) -> None:
    client, kp, _ks, _store = sov
    ptok = _mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")  # parent → admin:*
    r = await client.post(
        "/admin/policy/grant",
        json={
            "issuer": "shaz-cabal", "persona": "rook",
            "scopes": ["mem:query"], "allowed_handlers": ["scratchpad"],
        },
        headers=_hdr(ptok),
    )
    assert r.status_code == 200, r.text
    grants = (await client.get("/admin/policy", headers=_hdr(ptok))).json()["grants"]
    assert any(g["issuer"] == "shaz-cabal" and g["persona"] == "rook" for g in grants)


@pytest.mark.asyncio
async def test_admin_denied_for_nonparent(sov) -> None:
    client, _kp, ks, _store = sov
    tok = _mint(ks, iss="shaz-cabal")  # authenticates, but not a parent issuer
    r = await client.post(
        "/admin/policy/grant",
        json={"issuer": "shaz-cabal", "persona": "rook", "scopes": ["mem:query"]},
        headers=_hdr(tok),
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_parent_row_immutable(sov) -> None:
    client, kp, _ks, _store = sov
    ptok = _mint(kp, iss="rd-cabal")
    r = await client.post(
        "/admin/policy/revoke",
        json={"issuer": "rd-cabal", "persona": "*"},
        headers=_hdr(ptok),
    )
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_admin_audit_records_grant(sov) -> None:
    client, kp, _ks, _store = sov
    ptok = _mint(kp, iss="rd-cabal")
    await client.post(
        "/admin/policy/grant",
        json={"issuer": "kyle-cabal", "persona": "*", "scopes": ["mem:query"]},
        headers=_hdr(ptok),
    )
    actions = {
        row["action"]
        for row in (await client.get("/admin/policy/audit", headers=_hdr(ptok))).json()["audit"]
    }
    assert "grant" in actions


# ---- create_app invariant (Prudence #3) -----------------------------------


def test_multi_issuer_requires_policy_store() -> None:
    kp = _key()
    verifier = MultiIssuerJWKSVerifier(
        registry={
            "rd-cabal": StaticKeySetVerifier(key_set=KeySet([kp]), expected_issuer="rd-cabal")
        },
        parents=frozenset({"rd-cabal"}),
    )
    with pytest.raises(RuntimeError, match="requires a policy_store"):
        create_app(jwt_verifier=verifier)  # no policy_store → refuse


# ---- Critical: token sandbox boundaries ignored under a grant --------------


@pytest.mark.asyncio
async def test_token_tool_extras_ignored_under_grant(tmp_path) -> None:
    """A granted foreign token cannot choose a handler's sandbox boundary via
    tool_extras — the server supplies it (policy_tool_extras); the token can't."""
    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "p.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "echo", _EchoExtraHandler())
    app = create_app(
        jwt_verifier=_verifier(kp, ks), registry=reg, policy_store=store,
        policy_tool_extras={"memory.db_path": "/server/set/path"},
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await store.grant("shaz-cabal", "rook", scopes=set(), allowed_handlers={"echo"})
        tok = _mint(
            ks, iss="shaz-cabal",
            tool_extras={"memory.db_path": "/rooks/private.db", "files.allowed_paths": ["/etc"]},
        )
        raw = (await _rpc(client, tok, "tools/call", {"name": "echo.peek", "arguments": {}})).text
    store.close()
    assert "/rooks/private.db" not in raw   # token's db_path never reached the handler
    assert "/etc" not in raw                # token's allowed_paths ignored
    assert "/server/set/path" in raw        # server-configured value used instead


# ---- Important #3: route-level scope gate + admin revoke ------------------


@pytest.mark.asyncio
async def test_scope_gate_refuses_and_audits(tmp_path) -> None:
    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "p.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    app = create_app(
        jwt_verifier=_verifier(kp, ks), registry=reg, policy_store=store,
        # #42: the resolver now receives the full tool name "<handler>.<tool>".
        policy_scope_for=lambda name: (
            "mem:append" if name.split(".", 1)[0] == "scratchpad" else None
        ),
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Granted the handler, but only mem:query — the scratchpad handler needs mem:append.
        await store.grant("shaz-cabal", "rook", scopes={"mem:query"}, allowed_handlers={"scratchpad"})
        tok = _mint(ks, iss="shaz-cabal")
        err = (
            await _rpc(client, tok, "tools/call", {"name": "scratchpad.set", "arguments": {}})
        ).json()["error"]
        assert "scope 'mem:append' required" in err["message"]
        denies = [r for r in await store.audit(limit=20) if r.action == "access_deny"]
    store.close()
    assert any(d.detail.get("required_scope") == "mem:append" for d in denies)


@pytest.mark.asyncio
async def test_per_tool_scope_split_query_vs_append(tmp_path) -> None:
    """#42 CORE PROOF: a grant of {mem:query} passes the scope gate for
    memory.recall (read) but is DENIED memory.commit (write, needs mem:append)
    — the read/write split enforced per TOOL, with the scope map derived from
    the memory card's per-tool required_scope (no policy_scope_for injected).
    """
    from liminal.handlers.memory import MemoryHandler

    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "p.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "memory", MemoryHandler())
    app = create_app(jwt_verifier=_verifier(kp, ks), registry=reg, policy_store=store)

    # Derived per-tool scopes (no injection).
    assert app.state.policy_scope_for("memory.recall") == "mem:query"
    assert app.state.policy_scope_for("memory.commit") == "mem:append"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Grant mem:query only; both memory tools allowed at the handler level.
        await store.grant(
            "shaz-cabal", "rook", scopes={"mem:query"}, allowed_handlers={"memory"}
        )
        tok = _mint(ks, iss="shaz-cabal")

        # commit needs mem:append → REFUSED at the scope gate (never dispatches).
        err = (
            await _rpc(client, tok, "tools/call", {"name": "memory.commit", "arguments": {}})
        ).json()["error"]
        assert "scope 'mem:append' required for tool 'memory.commit'" in err["message"]

        # recall needs mem:query (held) → the scope gate ADMITS it; any error is
        # downstream, NOT a scope refusal.
        recall = (
            await _rpc(client, tok, "tools/call", {"name": "memory.recall", "arguments": {"query": "x"}})
        ).json()
        recall_msg = (recall.get("error") or {}).get("message", "")
        assert "required for tool" not in recall_msg, recall_msg

        denies = [r for r in await store.audit(limit=20) if r.action == "access_deny"]
    store.close()
    assert any(
        d.detail.get("tool") == "memory.commit"
        and d.detail.get("required_scope") == "mem:append"
        for d in denies
    )


@pytest.mark.asyncio
async def test_admin_revoke_nonparent_grant(sov) -> None:
    client, kp, _ks, store = sov
    ptok = _mint(kp, iss="rd-cabal")
    await client.post(
        "/admin/policy/grant",
        json={"issuer": "shaz-cabal", "persona": "rook", "scopes": ["mem:query"]},
        headers=_hdr(ptok),
    )
    r = await client.post(
        "/admin/policy/revoke",
        json={"issuer": "shaz-cabal", "persona": "rook"},
        headers=_hdr(ptok),
    )
    assert r.status_code == 200
    assert await store.resolve("shaz-cabal", "rook") is None


# ---- inbound correlation-id at the boundary (#27 inbound half, Prudence #29) ----


@pytest.mark.asyncio
async def test_inbound_correlation_id_reaches_ctx_extra(tmp_path) -> None:
    """An inbound x-correlation-id header must reach ctx.extra at the server
    boundary — proven THROUGH the HTTP route (not by setting ctx.extra directly),
    so end-to-end trace continuity across the multiplexer->target hop holds."""
    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "p.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "echo", _EchoExtraHandler())
    app = create_app(jwt_verifier=_verifier(kp, ks), registry=reg, policy_store=store)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await store.grant("shaz-cabal", "rook", scopes=set(), allowed_handlers={"echo"})
        tok = _mint(ks, iss="shaz-cabal")
        r = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "echo.peek", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {tok}", "x-correlation-id": "trace-abc-123"},
        )
        raw = r.text
    store.close()
    assert "trace-abc-123" in raw, "inbound x-correlation-id must reach ctx.extra"


# ---- mixed-kind authz: the allowed_handlers gate applies to a federated target ----


class _StubTarget:
    """A non-in-process Target double — stands in for a federated (http/stdio)
    target so the allowed_handlers gate can be exercised across a target kind
    that ISN'T InProcessTarget. The gate is at the Multiplexer/routes layer
    (keyed on target name), so a stub is a sufficient double."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.trust = TrustTier.UNTRUSTED

    async def startup(self) -> None: ...
    async def shutdown(self) -> None: ...

    async def list_tools(self) -> list[ToolSpec]:
        return [ToolSpec(name="do", description="federated tool", input_schema={"type": "object", "properties": {}})]

    async def dispatch(self, tool: str, payload: dict, ctx: Context) -> ToolResult:
        return ToolResult.json({"ok": True})

    def protocol_version(self) -> str | None:
        return None


@pytest.mark.asyncio
async def test_mixed_kind_authz_gates_federated_target(tmp_path) -> None:
    """grant.allowed_handlers gates a FEDERATED (non-in-process) target's tools
    identically to in-process ones — the one federation-authz invariant not
    otherwise exercised across a target kind (Prudence #29)."""
    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "p.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    app = create_app(jwt_verifier=_verifier(kp, ks), registry=reg, policy_store=store)
    # Inject a federated-kind target alongside the in-process one.
    app.state.dispatcher = Multiplexer(
        [InProcessTarget(name="scratchpad", handler=ScratchpadHandler()), _StubTarget("federated")]
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Grant only scratchpad — NOT the federated target.
        await store.grant("shaz-cabal", "rook", scopes=set(), allowed_handlers={"scratchpad"})
        tok = _mint(ks, iss="shaz-cabal")
        tools = (await _rpc(client, tok, "tools/list")).json()["result"]["tools"]
        assert all(not t["name"].startswith("federated.") for t in tools), tools
        assert any(t["name"].startswith("scratchpad.") for t in tools)
        err = (
            await _rpc(client, tok, "tools/call", {"name": "federated.do", "arguments": {}})
        ).json()["error"]
        # Pin the *reason*: refused by the allowlist gate, not an incidental miss.
        assert err["code"] == ERROR_UNKNOWN_TOOL
        assert "federated" in err["message"]
    store.close()


# ---- #61 / #44: discovery mirrors the scope gate; one audit key ------------

# scratchpad.set needs mem:append, scratchpad.clear hits the deny-by-default
# sentinel, get/list need nothing. Injected so the test pins the ROUTE, not the
# card-derived map.
def _scratchpad_scopes(name: str) -> str | None:
    from liminal.server.scopes import DENY_SCOPE

    return {"scratchpad.set": "mem:append", "scratchpad.clear": DENY_SCOPE}.get(name)


async def _scoped_app(tmp_path):
    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "p.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    register_explicit(reg, "echo", _EchoExtraHandler())  # outside the allowlist
    app = create_app(
        jwt_verifier=_verifier(kp, ks), registry=reg, policy_store=store,
        policy_scope_for=_scratchpad_scopes,
    )
    return app, ks, store


async def _listed(client, tok) -> set[str]:
    body = (await _rpc(client, tok, "tools/list")).json()
    return {t["name"] for t in body["result"]["tools"]}


@pytest.mark.asyncio
async def test_tools_list_hides_what_the_scope_gate_refuses(tmp_path) -> None:
    """#61: what a persona sees == what it can call. For every tool in the
    catalog, it is listed exactly when tools/call gets past both authz gates."""
    app, ks, store = await _scoped_app(tmp_path)
    all_tools = {
        "scratchpad.set", "scratchpad.get", "scratchpad.list", "scratchpad.clear",
        "echo.peek",
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await store.grant("shaz-cabal", "rook", scopes={"mem:query"}, allowed_handlers={"scratchpad"})
        tok = _mint(ks, iss="shaz-cabal")
        listed = await _listed(client, tok)
        assert listed == {"scratchpad.get", "scratchpad.list"}
        for name in all_tools:
            resp = (await _rpc(client, tok, "tools/call", {"name": name, "arguments": {"key": "k"}})).json()
            msg = (resp.get("error") or {}).get("message", "")
            refused = any(
                s in msg for s in (
                    "not in persona's allowed_handlers",  # handler allowlist
                    "required for tool",                   # scope gate
                    "not named in the scope map",          # deny sentinel
                )
            )
            assert refused == (name not in listed), (name, msg)
    store.close()


@pytest.mark.asyncio
async def test_tools_list_shows_everything_to_a_grant_holding_the_scopes(tmp_path) -> None:
    """The filter hides only what the gate refuses: admin:* satisfies every
    requirement (the sentinel included), so nothing is hidden."""
    app, ks, store = await _scoped_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await store.grant("shaz-cabal", "rook", scopes={"admin:*"}, allowed_handlers={"scratchpad"})
        tok = _mint(ks, iss="shaz-cabal")
        assert await _listed(client, tok) == {
            "scratchpad.set", "scratchpad.get", "scratchpad.list", "scratchpad.clear"
        }
    store.close()


@pytest.mark.asyncio
async def test_every_access_deny_carries_the_handler_key(tmp_path) -> None:
    """#44: both access_deny paths (handler allowlist, scope gate -- both of its
    shapes) record detail["handler"], and the scope gate keeps detail["tool"]."""
    app, ks, store = await _scoped_app(tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await store.grant("shaz-cabal", "rook", scopes={"mem:query"}, allowed_handlers={"scratchpad"})
        tok = _mint(ks, iss="shaz-cabal")
        for name in ("scratchpad.set", "scratchpad.clear", "echo.peek"):
            await _rpc(client, tok, "tools/call", {"name": name, "arguments": {}})
        denies = [r.detail for r in await store.audit(limit=20) if r.action == "access_deny"]
    store.close()
    assert len(denies) == 3, denies
    assert {d["handler"] for d in denies} == {"scratchpad", "echo"}
    scope_denies = [d for d in denies if d["handler"] == "scratchpad"]
    assert {d["tool"] for d in scope_denies} == {"scratchpad.set", "scratchpad.clear"}


# ---- liminal#143: credentials are not resolved for a non-parent issuer ----


class _EchoCredsHandler:
    """Returns ctx.credentials so a test can see what the route resolved."""

    def tools(self) -> list[ToolSpec]:
        return [ToolSpec(name="dump", description="echo ctx.credentials")]

    def capability_card(self) -> dict:
        return {
            "handler": "creds",
            "description": "echoes ctx.credentials for tests",
            "tools": [{"name": "dump", "description": "echo ctx.credentials"}],
        }

    async def dispatch(self, name: str, payload: dict, ctx: Context) -> ToolResult:
        return ToolResult.json({"creds": dict(ctx.credentials)})


@pytest.mark.asyncio
async def test_foreign_issuer_same_persona_gets_no_home_credentials(tmp_path) -> None:
    """A granted foreign issuer presenting the home persona's name ("rook")
    must not receive the secrets Cabal holds for home rook: the route does not
    call the resolver for a non-parent issuer. The parent issuer's rook still
    gets them, and its fetch is keyed by issuer."""
    import json

    import httpx

    from liminal.server.credentials import CabalCoreCredentialResolver

    cabal_hits: list[str] = []

    def cabal(request: httpx.Request) -> httpx.Response:
        cabal_hits.append(request.url.path)
        # Cabal keys secrets by persona name only: any "rook" gets home rook's.
        return httpx.Response(
            200, json={"credentials": {"NOTIFY_WEBHOOK_URL": "https://hooks.example/home-rook-secret"}}
        )

    resolver = CabalCoreCredentialResolver(
        cabal_url="http://cabal-test",
        token_provider=lambda: "t",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(cabal)),
    )
    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "p.db"), parent_issuer="rd-cabal")
    reg = Registry()
    register_explicit(reg, "creds", _EchoCredsHandler())
    app = create_app(
        jwt_verifier=_verifier(kp, ks), registry=reg, policy_store=store,
        credential_resolver=resolver.fetch,
    )
    call = {"name": "creds.dump", "arguments": {}}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Default issuer-wide grant shape (persona "*"), as in the issue.
        await store.grant("shaz-cabal", "*", scopes=set(), allowed_handlers={"creds"})
        await store.grant("rd-cabal", "rook", scopes=set(), allowed_handlers={"creds"})

        foreign = (await _rpc(client, _mint(ks, iss="shaz-cabal", persona="rook"), "tools/call", call)).json()
        assert foreign.get("error") is None, foreign
        assert json.loads(foreign["result"]["content"][0]["text"])["creds"] == {}
        assert cabal_hits == []  # the resolver never reached Cabal

        home = (await _rpc(client, _mint(kp, iss="rd-cabal", persona="rook"), "tools/call", call)).json()
        assert home.get("error") is None, home
        assert json.loads(home["result"]["content"][0]["text"])["creds"] == {
            "NOTIFY_WEBHOOK_URL": "https://hooks.example/home-rook-secret"
        }
        assert cabal_hits == ["/admin/secrets/rook/creds"]
        assert set(resolver._cache) == {("rd-cabal", "rook", "creds")}
    await resolver.aclose()
    store.close()
