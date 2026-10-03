"""Demoting a parent issuer (liminal#87) — the issuer dimension of the
narrowing guard.

_seed_parent's narrowing check compares personas WHERE issuer = ?, so it could
never see a demoted parent: that issuer's is_parent rows survived, parents()
kept answering for it, and a persona it minted still passed the guardian gate.
The store now reconciles parent rows against the configured parent across ALL
issuers and refuses to open on any mismatch, as the persona dimension does.
"""

from __future__ import annotations

import time

import pytest
from httpx import ASGITransport, AsyncClient
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from liminal.handlers.scratchpad import ScratchpadHandler
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import (
    MultiIssuerJWKSVerifier,
    ParentNarrowingConflict,
    SqlitePolicyStore,
    StaticKeySetVerifier,
    create_app,
)

from .test_blocker_set import SVC, _hdr, _key, _registry_toml

OLD = "home-cabal"
NEW = "new-cabal"


def _mint(key: RSAKey, *, issuer: str, persona: str) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "sub": f"{persona}-primus",
        "aud": SVC,
        "iat": now,
        "exp": now + 60,
        "cabal_persona": persona,
    }
    return jwt.encode({"alg": "RS256", "kid": key.kid, "typ": "JWT"}, payload, key)


def _parent_rows(db: str) -> set[tuple[str, str]]:
    import sqlite3

    conn = sqlite3.connect(db)
    try:
        return set(
            conn.execute(
                "SELECT issuer, persona FROM policy_grants WHERE is_parent = 1"
            ).fetchall()
        )
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_store_refuses_to_open_once_its_parent_issuer_is_demoted(tmp_path) -> None:
    """The issue's scenario. Boot 1: OLD is the parent and its room-operator
    administers (200 on GET /admin/policy). Boot 2: the registry demotes OLD
    and names NEW as parent. Before the fix the store opened, still listed OLD
    in parents(), and the same token got 200 again plus a working admin:*
    grant. Now the store refuses to open, so that server never serves."""
    old_key, new_key = _key(), _key()
    db = str(tmp_path / "policy.db")

    def _verifier(parent: str) -> MultiIssuerJWKSVerifier:
        return MultiIssuerJWKSVerifier(
            registry={
                OLD: StaticKeySetVerifier(
                    key_set=KeySet([old_key]), expected_issuer=OLD, expected_audience=SVC
                ),
                NEW: StaticKeySetVerifier(
                    key_set=KeySet([new_key]), expected_issuer=NEW, expected_audience=SVC
                ),
            },
            parents=frozenset({parent}),
        )

    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    operator = _mint(old_key, issuer=OLD, persona="room-operator")

    # Boot 1: the baseline, so the refusal below is not vacuous.
    store = SqlitePolicyStore(db, parent_issuer=OLD, parent_personas=("room-operator",))
    try:
        app = create_app(jwt_verifier=_verifier(OLD), registry=reg, policy_store=store)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            assert (await client.get("/admin/policy", headers=_hdr(operator))).status_code == 200
    finally:
        store.close()

    # Boot 2: OLD demoted. The store must refuse rather than keep OLD a parent.
    with pytest.raises(ParentNarrowingConflict) as exc:
        SqlitePolicyStore(db, parent_issuer=NEW, parent_personas=("new-operator",))
    assert OLD in str(exc.value)
    assert "new database" in str(exc.value)


def test_cli_refuses_to_serve_with_a_demoted_parent_issuer(
    monkeypatch, tmp_path, capsys
) -> None:
    """Demoted: OLD stays in the registry as a data-plane issuer, NEW becomes
    the parent. The CLI renders the refusal as exit 2 and names OLD."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    db = str(tmp_path / "p.db")
    boot1 = _registry_toml(
        tmp_path, issuers=[OLD, NEW], parent=OLD, admin_personas=["room-operator"]
    )
    assert main(["serve", "--trust-registry", boot1, "--policy-db", db]) == 0
    capsys.readouterr()

    boot2 = _registry_toml(
        tmp_path, issuers=[OLD, NEW], parent=NEW, admin_personas=["new-operator"]
    )
    rc = main(["serve", "--trust-registry", boot2, "--policy-db", db])
    assert rc == 2, "demoting the parent issuer must REFUSE, not no-op"
    err = capsys.readouterr().err
    assert repr(OLD) in err, "the refusal must name the demoted issuer"
    assert "new database" in err


def test_cli_refuses_to_serve_with_the_parent_issuer_removed(
    monkeypatch, tmp_path, capsys
) -> None:
    """Removed entirely: OLD is gone from the registry, so its tokens no longer
    verify — but its rows would still sit in parents(), ready to answer if OLD
    is ever re-added as a plain issuer. Same refusal."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    db = str(tmp_path / "p.db")
    boot1 = _registry_toml(
        tmp_path, issuers=[OLD, NEW], parent=OLD, admin_personas=["room-operator"]
    )
    assert main(["serve", "--trust-registry", boot1, "--policy-db", db]) == 0
    capsys.readouterr()

    boot2 = _registry_toml(
        tmp_path, issuers=[NEW], parent=NEW, admin_personas=["new-operator"]
    )
    rc = main(["serve", "--trust-registry", boot2, "--policy-db", db])
    assert rc == 2
    assert repr(OLD) in capsys.readouterr().err


def test_a_new_policy_db_adopts_the_new_parent(monkeypatch, tmp_path, capsys) -> None:
    """The remedy the refusal names must actually work: the same demoting
    registry against a NEW --policy-db serves."""
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)
    from liminal.cli import main

    boot1 = _registry_toml(
        tmp_path, issuers=[OLD, NEW], parent=OLD, admin_personas=["room-operator"]
    )
    assert main(["serve", "--trust-registry", boot1, "--policy-db", str(tmp_path / "a.db")]) == 0
    boot2 = _registry_toml(
        tmp_path, issuers=[OLD, NEW], parent=NEW, admin_personas=["new-operator"]
    )
    assert main(["serve", "--trust-registry", boot2, "--policy-db", str(tmp_path / "b.db")]) == 0


def test_refusal_writes_nothing_and_the_configured_parent_is_unaffected(tmp_path) -> None:
    """The check runs before seeding: a refused boot must not leave NEW's rows
    half-seeded, and reopening with the original parent still works."""
    from liminal.server import ParentIssuerDemoted

    db = str(tmp_path / "p.db")
    SqlitePolicyStore(db, parent_issuer=OLD, parent_personas=("room-operator",)).close()
    before = _parent_rows(db)

    with pytest.raises(ParentIssuerDemoted):
        SqlitePolicyStore(db, parent_issuer=NEW, parent_personas=("new-operator",))
    assert _parent_rows(db) == before == {(OLD, "room-operator")}

    s = SqlitePolicyStore(db, parent_issuer=OLD, parent_personas=("room-operator",))
    try:
        assert s.parents() == frozenset({OLD})
    finally:
        s.close()


def test_no_configured_parent_refuses_existing_parent_rows(tmp_path) -> None:
    """Opening without a parent means nothing may hold parent standing, so any
    surviving parent row is a demotion. A fresh store without a parent opens."""
    from liminal.server import ParentIssuerDemoted

    SqlitePolicyStore(str(tmp_path / "fresh.db")).close()

    db = str(tmp_path / "p.db")
    SqlitePolicyStore(db, parent_issuer=OLD).close()
    with pytest.raises(ParentIssuerDemoted):
        SqlitePolicyStore(db)
