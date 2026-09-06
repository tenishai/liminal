"""The blocker set (liminal#73, #74, #77) — end-to-end and CLI conduct.

#73: parent rows never resolve on the data plane, admin standing is
per-persona, and the home topology (the parent issuer is also the issuer of
every agent token) cannot fail open. #74: the admin surface can leave the
data-plane listener entirely. #77: the single-issuer audience is a knob, not
a constant.
"""

from __future__ import annotations

import time

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from liminal.handlers.scratchpad import ScratchpadHandler
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import (
    MultiIssuerJWKSVerifier,
    SqlitePolicyStore,
    StaticKeySetVerifier,
    create_admin_app,
    create_app,
)

SVC = "liminal@home"
HOME = "home-cabal"


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


def _mint(key: RSAKey, *, persona: str, ttl: int = 60) -> str:
    now = int(time.time())
    payload = {
        "iss": HOME,
        "sub": f"{persona}-primus",
        "aud": SVC,
        "iat": now,
        "exp": now + ttl,
        "cabal_persona": persona,
    }
    return jwt.encode({"alg": "RS256", "kid": key.kid, "typ": "JWT"}, payload, key)


def _hdr(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


@pytest_asyncio.fixture
async def home(tmp_path):
    """The home topology: ONE issuer, both parent and agent-token signer —
    exactly the deployment where the pre-fix wildcard fallback handed
    admin:* to every ungranted agent. Admin standing is narrowed to the
    room-operator persona."""
    key = _key()
    verifier = MultiIssuerJWKSVerifier(
        registry={
            HOME: StaticKeySetVerifier(
                key_set=KeySet([key]), expected_issuer=HOME, expected_audience=SVC
            ),
        },
        parents=frozenset({HOME}),
    )
    store = SqlitePolicyStore(
        str(tmp_path / "policy.db"),
        parent_issuer=HOME,
        parent_personas=("room-operator",),
    )
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    app = create_app(jwt_verifier=verifier, registry=reg, policy_store=store)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, key, store


async def _call_tool(client, tok):
    return await client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "scratchpad.write", "arguments": {"text": "x"}},
        },
        headers=_hdr(tok),
    )


@pytest.mark.asyncio
async def test_home_topology_ungranted_agent_gets_nothing(home) -> None:
    """The #73 regression, over HTTP: an ungranted agent of the home issuer
    is denied on the data plane AND on the admin surface."""
    client, key, _store = home
    agent = _mint(key, persona="some-agent")

    dispatch = await _call_tool(client, agent)
    body = dispatch.json()
    assert "error" in body, body
    assert "no policy grant" in str(body["error"]).lower()

    admin = await client.get("/admin/policy", headers=_hdr(agent))
    assert admin.status_code == 403


@pytest.mark.asyncio
async def test_home_topology_operator_admins_but_does_not_dispatch(home) -> None:
    """Parent standing is admin standing only: the named admin persona
    reaches /admin/*, and holds NO data-plane grant by parenthood."""
    client, key, _store = home
    operator = _mint(key, persona="room-operator")

    admin = await client.get("/admin/policy", headers=_hdr(operator))
    assert admin.status_code == 200
    rows = admin.json()["grants"]
    assert any(r["is_parent"] and r["persona"] == "room-operator" for r in rows)

    dispatch = await _call_tool(client, operator)
    body = dispatch.json()
    assert "error" in body and "no policy grant" in str(body["error"]).lower()


@pytest.mark.asyncio
async def test_home_topology_granted_agent_dispatches_without_admin(home) -> None:
    client, key, store = home
    await store.grant(
        HOME, "worker", scopes={"scratch:write"}, allowed_handlers=None
    )
    worker = _mint(key, persona="worker")

    dispatch = await _call_tool(client, worker)
    assert "error" not in dispatch.json() or "no policy grant" not in str(
        dispatch.json().get("error", "")
    )

    admin = await client.get("/admin/policy", headers=_hdr(worker))
    assert admin.status_code == 403


@pytest.mark.asyncio
async def test_mount_admin_false_keeps_admin_off_the_data_plane(tmp_path) -> None:
    """#74: with mount_admin=False the data-plane app carries no /admin/*
    route at all; create_admin_app serves the same guardian gate alone."""
    key = _key()
    verifier = MultiIssuerJWKSVerifier(
        registry={
            HOME: StaticKeySetVerifier(
                key_set=KeySet([key]), expected_issuer=HOME, expected_audience=SVC
            ),
        },
        parents=frozenset({HOME}),
    )
    store = SqlitePolicyStore(
        str(tmp_path / "policy.db"),
        parent_issuer=HOME,
        parent_personas=("room-operator",),
    )
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    data_app = create_app(
        jwt_verifier=verifier, registry=reg, policy_store=store, mount_admin=False
    )
    admin_app = create_admin_app(jwt_verifier=verifier, policy_store=store)
    operator = _mint(key, persona="room-operator")

    async with AsyncClient(
        transport=ASGITransport(app=data_app), base_url="http://test"
    ) as data_client:
        resp = await data_client.get("/admin/policy", headers=_hdr(operator))
        assert resp.status_code == 404

    async with AsyncClient(
        transport=ASGITransport(app=admin_app), base_url="http://test"
    ) as admin_client:
        resp = await admin_client.get("/admin/policy", headers=_hdr(operator))
        assert resp.status_code == 200


# ---- CLI conduct (#77 audience knob, #73 guard, #74 listener split) --------


def _registry_toml(tmp_path, *, issuers: list[str], parent: str, admin_personas=None):
    lines = [f'service_audience = "{SVC}"']
    for issuer in issuers:
        lines.append("[[issuer]]")
        lines.append(f'id = "{issuer}"')
        lines.append(f'jwks_uri = "https://{issuer}.example/jwks.json"')
        if issuer == parent:
            lines.append("parent = true")
            if admin_personas is not None:
                rendered = ", ".join(f'"{p}"' for p in admin_personas)
                lines.append(f"admin_personas = [{rendered}]")
    path = tmp_path / "registry.toml"
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def test_serve_audience_flag_reaches_the_verifier(monkeypatch, tmp_path) -> None:
    """#77: --audience configures the single-issuer verifier; the default
    stays the historical constant."""
    import uvicorn

    captured: dict = {}
    monkeypatch.setattr(
        uvicorn, "run", lambda app, **kw: captured.update(app=app, **kw)
    )
    from liminal.cli import main

    rc = main(
        [
            "serve",
            "--jwks-url",
            "https://issuer.example/jwks.json",
            "--audience",
            "liminal-room",
        ]
    )
    assert rc == 0
    assert captured["app"].state.jwt_verifier.expected_audience == "liminal-room"

    rc = main(["serve", "--jwks-url", "https://issuer.example/jwks.json"])
    assert rc == 0
    assert captured["app"].state.jwt_verifier.expected_audience == "liminal"


def test_sole_parent_registry_without_admin_personas_exits_2(
    monkeypatch, tmp_path, capsys
) -> None:
    """#73 guard: one trusted issuer that is also the parent, and no
    admin_personas — every accepted token would double as an admin token.
    Refused at boot with a diagnostic, not served."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    registry = _registry_toml(tmp_path, issuers=[HOME], parent=HOME)
    rc = main(
        [
            "serve",
            "--trust-registry",
            registry,
            "--policy-db",
            str(tmp_path / "p.db"),
        ]
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "admin_personas" in err


def test_multi_issuer_registry_without_admin_personas_is_REFUSED(
    monkeypatch, tmp_path, capsys
) -> None:
    """DELIBERATE BEHAVIOUR CHANGE (Prudence, #83 round 1, Critical 2).

    This test previously asserted rc == 0 with a warning — it PINNED THE
    VULNERABLE BEHAVIOUR. The graduated guard keyed on `len(issuers)`, which is
    not the hazard's axis: adding an unrelated second issuer downgraded refusal
    to a warning while reducing the parent's own agents' exposure not at all.
    Driven against the real CLI, an ungranted agent then got 200 on
    /admin/policy, self-granted admin:*, dispatched, and revoked the partner
    cabal.

    Every issuer in the registry is a data-plane issuer, so the parent always
    signs data-plane tokens; without admin_personas every persona it mints
    holds admin standing, at one issuer and at ten. The multi-issuer case must
    refuse for the same reason the single-issuer case does.
    """
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    registry = _registry_toml(
        tmp_path, issuers=["rd-cabal", "shaz-cabal"], parent="rd-cabal"
    )
    rc = main(
        [
            "serve",
            "--trust-registry",
            registry,
            "--policy-db",
            str(tmp_path / "p.db"),
        ]
    )
    assert rc == 2, "a multi-issuer registry without admin_personas must REFUSE"
    err = capsys.readouterr().err
    assert "admin_personas" in err
    # The message must say the issuer count is irrelevant, since believing
    # otherwise is exactly what made this a warning.
    assert "independent of how many other issuers" in err


def test_admin_personas_narrowing_an_existing_wildcard_store_is_REFUSED(
    monkeypatch, tmp_path, capsys
) -> None:
    """Prudence, #83 round 1, Critical 1. Seeding is idempotent per
    (issuer, persona), so adding admin_personas to a store already carrying a
    WILDCARD parent row adds the named rows and leaves the wildcard answering
    for everyone — narrowed in appearance, unchanged in effect.

    The sting is that setting admin_personas ALSO silences the boot warning, so
    the operator does exactly what the warning asks, gets no warning back, and
    remains fully exposed. Control and compensating signal fail together.
    """
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    db = str(tmp_path / "wild.db")

    # 1. Seed a store the historical way: wildcard parent row.
    from liminal.server import SqlitePolicyStore

    store = SqlitePolicyStore(db, parent_issuer="rd-cabal")
    store.close()

    # 2. Now try to narrow it in place, which is the upgrade path an operator
    #    takes after reading the warning.
    registry = _registry_toml(
        tmp_path,
        issuers=["rd-cabal", "shaz-cabal"],
        parent="rd-cabal",
        admin_personas=["room-operator"],
    )
    rc = main(["serve", "--trust-registry", registry, "--policy-db", db])
    assert rc == 2, "narrowing a wildcard-seeded store in place must REFUSE"
    err = capsys.readouterr().err
    assert "already holds parent row(s)" in err
    assert "'*'" in err, "the refusal must name the row it is protecting"
    assert "new database" in err


def test_de_listing_a_named_admin_persona_is_REFUSED(
    monkeypatch, tmp_path, capsys
) -> None:
    """Prudence, #83 round 2 Critical. The first version of the narrowing check
    fired only when the EXISTING row was the wildcard — closed in one direction
    only, and the open direction is the one an operator actually travels.

    Rotating someone out of admin is the ordinary case: seed with two named
    admins, then edit the registry to drop one. Seeding is idempotent per
    (issuer, persona) and rows are immutable, so the dropped persona's row
    survived, resolve_parent kept answering for it, and the running server never
    re-consults the registry. Driven over the real HTTP surface by the reviewer:
    the de-listed persona's token got 200 on /admin/policy and granted admin:*
    to a partner cabal.
    """
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    db = str(tmp_path / "rotate.db")
    reg_two = _registry_toml(
        tmp_path,
        issuers=["rd-cabal", "shaz-cabal"],
        parent="rd-cabal",
        admin_personas=["room-operator", "old-admin"],
    )
    assert main(["serve", "--trust-registry", reg_two, "--policy-db", db]) == 0
    capsys.readouterr()

    # Now rotate `old-admin` out — an explicit revocation. _registry_toml
    # rewrites the same path, so this is the operator editing their registry.
    reg_one = _registry_toml(
        tmp_path,
        issuers=["rd-cabal", "shaz-cabal"],
        parent="rd-cabal",
        admin_personas=["room-operator"],
    )
    rc = main(["serve", "--trust-registry", reg_one, "--policy-db", db])
    assert rc == 2, "de-listing a named admin persona must REFUSE, not no-op"
    err = capsys.readouterr().err
    assert "old-admin" in err, "the refusal must name the persona being dropped"
    assert "new database" in err


def test_widening_the_admin_set_is_permitted(monkeypatch, tmp_path, capsys) -> None:
    """The counterpart: refusing on ANY removal must not refuse an ADDITION.
    {"a"} -> {"a","b"} drops nothing, so it is permitted — otherwise the fix
    would block the one narrowing-adjacent edit that is always safe."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    db = str(tmp_path / "widen.db")
    one = _registry_toml(
        tmp_path, issuers=["rd-cabal", "shaz-cabal"], parent="rd-cabal",
        admin_personas=["room-operator"],
    )
    assert main(["serve", "--trust-registry", one, "--policy-db", db]) == 0
    capsys.readouterr()

    two = _registry_toml(
        tmp_path, issuers=["rd-cabal", "shaz-cabal"], parent="rd-cabal",
        admin_personas=["room-operator", "second-admin"],
    )
    assert main(["serve", "--trust-registry", two, "--policy-db", db]) == 0, (
        "widening the admin set drops nothing and must be permitted"
    )


def test_explicit_wildcard_admin_personas_warns(monkeypatch, tmp_path, capsys) -> None:
    """Prudence, #83 round 2 Important 1. `admin_personas = ["*"]` is TRUTHY, so
    it passes the missing-admin_personas guard and then seeds the historical
    wildcard row — reaching exactly the state that error calls unacceptable,
    with LESS signal than before this branch, since the old graduated code
    warned in this topology and that warning went away with it.

    It stays PERMITTED (admin.py calls a wildcard parent row an explicit
    deployment choice) but it must not be silent, because it is the choice an
    operator makes to silence the error when they have no persona name to hand.
    """
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    registry = _registry_toml(
        tmp_path, issuers=["rd-cabal", "shaz-cabal"], parent="rd-cabal",
        admin_personas=["*"],
    )
    rc = main(
        ["serve", "--trust-registry", registry, "--policy-db", str(tmp_path / "w.db")]
    )
    assert rc == 0, "an explicit wildcard is permitted, not refused"
    err = capsys.readouterr().err
    assert "admin_personas" in err and "EVERY persona" in err, (
        "an explicit wildcard must warn — it is the state the error refuses"
    )


def test_the_guard_comment_does_not_advocate_the_removed_rule() -> None:
    """Prudence, #83 round 2 Important 2. The comment above the guard still
    described the GRADUATED behaviour that round 1 called Critical 2 and this
    branch removed — eight lines above a comment saying the opposite, with the
    stale one met first. A maintainer reading top-down would learn the removed
    rule as the design, which is the path back to reintroducing it.

    Asserted on the source because the defect is a comment, and nothing else
    can see it.
    """
    import pathlib as _pl

    cli = (_pl.Path(__file__).resolve().parents[1] / "src" / "liminal" / "cli.py").read_text()
    # Normalise: the guard's message is split across adjacent string literals,
    # so the rendered phrase never appears contiguously in the source.
    flat = " ".join(cli.split())
    assert "warned about loudly" not in flat, (
        "the guard comment still advocates the graduated behaviour that "
        "round-1 Critical 2 identified as the defect"
    )
    assert "refused when the parent is the only trusted" not in flat, (
        "the guard comment still describes refusal as scoped to a single issuer"
    )
    assert "independent of how many other " in flat, (
        "the guard's actual rule should be stated where the reader meets it"
    )


def test_admin_port_requires_trust_registry(monkeypatch, capsys) -> None:
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    rc = main(
        [
            "serve",
            "--jwks-url",
            "https://issuer.example/jwks.json",
            "--admin-port",
            "9101",
        ]
    )
    assert rc == 2
    assert "--admin-port" in capsys.readouterr().err


def test_admin_port_splits_the_surfaces(monkeypatch, tmp_path) -> None:
    """#74: with --admin-port, two listeners serve two apps — the data plane
    carries no /admin/* route; the admin app carries only the admin surface."""
    import uvicorn

    built: list = []

    class FakeConfig:
        def __init__(self, app, host=None, port=None, **_kw):
            self.app, self.host, self.port = app, host, port

    class FakeServer:
        def __init__(self, config):
            built.append(config)

        async def serve(self):
            return None

    monkeypatch.setattr(uvicorn, "Config", FakeConfig)
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    from liminal.cli import main

    registry = _registry_toml(
        tmp_path, issuers=[HOME], parent=HOME, admin_personas=["room-operator"]
    )
    rc = main(
        [
            "serve",
            "--trust-registry",
            registry,
            "--policy-db",
            str(tmp_path / "p.db"),
            "--admin-port",
            "9101",
        ]
    )
    assert rc == 0
    assert len(built) == 2
    by_port = {c.port: c.app for c in built}
    data_app, admin_app = by_port[9100], by_port[9101]

    # Route presence is probed over ASGI (introspecting app.routes no longer
    # sees lazily-included routers): 404 = the surface is absent; any
    # non-404 (here 401, no bearer supplied) = it is served. main() is sync
    # (it drives asyncio.run itself), so the probes get their own loop.
    import asyncio

    async def _probe() -> None:
        async with AsyncClient(
            transport=ASGITransport(app=data_app), base_url="http://t"
        ) as data_client:
            assert (await data_client.get("/admin/policy")).status_code == 404
            assert (await data_client.post("/mcp", json={})).status_code != 404
        async with AsyncClient(
            transport=ASGITransport(app=admin_app), base_url="http://t"
        ) as admin_client:
            assert (await admin_client.get("/admin/policy")).status_code == 401
            assert (await admin_client.post("/mcp", json={})).status_code == 404

    asyncio.run(_probe())
