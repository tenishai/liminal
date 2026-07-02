"""SqlitePolicyStore unit tests — federation Part 2 (limenal#20)."""

from __future__ import annotations

import asyncio
import time

import pytest

from limenal.server.policy import ParentImmutable, SqlitePolicyStore


@pytest.fixture
def store(tmp_path):
    s = SqlitePolicyStore(str(tmp_path / "policy.db"), parent_issuer="rd-cabal")
    yield s
    s.close()


@pytest.mark.asyncio
async def test_parent_seeded_admin_implies_all(store) -> None:
    assert store.parents() == frozenset({"rd-cabal"})
    g = await store.resolve("rd-cabal", "any-persona")  # issuer-wide parent row
    assert g is not None
    assert g.has_scope("admin:*")
    assert g.has_scope("mem:append")  # admin:* implies every scope


@pytest.mark.asyncio
async def test_precedence_exact_over_wildcard(store) -> None:
    await store.grant("shaz", "*", scopes={"mem:query"}, allowed_handlers=None)
    await store.grant(
        "shaz", "rook", scopes={"mem:query", "mem:append"}, allowed_handlers={"memory"}
    )
    exact = await store.resolve("shaz", "rook")
    assert exact.has_scope("mem:append")
    assert exact.allowed_handlers == frozenset({"memory"})

    wide = await store.resolve("shaz", "raven")  # falls back to (shaz, "*")
    assert wide.has_scope("mem:query")
    assert not wide.has_scope("mem:append")

    assert await store.resolve("unknown-cabal", "x") is None  # deny


@pytest.mark.asyncio
async def test_parent_row_immutable(store) -> None:
    with pytest.raises(ParentImmutable):
        await store.grant("rd-cabal", "*", scopes={"mem:query"}, allowed_handlers=None)
    with pytest.raises(ParentImmutable):
        await store.revoke("rd-cabal", "*")
    # Parent still intact + admin.
    assert (await store.resolve("rd-cabal", "x")).has_scope("admin:*")


@pytest.mark.asyncio
async def test_grant_revoke_roundtrip(store) -> None:
    await store.grant("kyle", "*", scopes={"mem:query"}, allowed_handlers=None)
    assert await store.resolve("kyle", "anyone") is not None
    await store.revoke("kyle", "*")
    assert await store.resolve("kyle", "anyone") is None
    # Revoking a non-existent grant is a no-op, not an error.
    await store.revoke("kyle", "*")


@pytest.mark.asyncio
async def test_allowed_handlers_none_vs_set(store) -> None:
    await store.grant("a", "*", scopes=set(), allowed_handlers=None)
    assert (await store.resolve("a", "x")).allowed_handlers is None  # all handlers
    await store.grant("b", "*", scopes=set(), allowed_handlers={"memory", "web"})
    assert (await store.resolve("b", "x")).allowed_handlers == frozenset({"memory", "web"})


@pytest.mark.asyncio
async def test_audit_records_and_filters(store) -> None:
    await store.grant("shaz", "rook", scopes={"mem:query"}, allowed_handlers=None)
    await store.record_access(
        issuer="shaz", persona="rook", agent="rook-primus", allowed=True, detail={"h": "memory"}
    )
    await store.record_access(
        issuer="shaz", persona="rook", agent="rook-primus", allowed=False, detail={"h": "notify"}
    )
    rows = await store.audit(limit=10)
    actions = {r.action for r in rows}
    assert {"grant", "access_allow", "access_deny"} <= actions


@pytest.mark.asyncio
async def test_list_grants_includes_parent(store) -> None:
    await store.grant("shaz", "rook", scopes={"mem:query"}, allowed_handlers=None)
    rows = await store.list_grants()
    parents = [r for r in rows if r.is_parent]
    assert len(parents) == 1 and parents[0].issuer == "rd-cabal"
    assert any(r.issuer == "shaz" and r.persona == "rook" for r in rows)


@pytest.mark.asyncio
async def test_audit_since_filter(store) -> None:
    await store.grant("shaz", "rook", scopes={"mem:query"}, allowed_handlers=None)
    await asyncio.sleep(0.02)
    mid = time.time()
    await asyncio.sleep(0.02)
    await store.grant("kyle", "rook", scopes={"mem:query"}, allowed_handlers=None)
    recent = {r.issuer for r in await store.audit(since=mid, limit=50)}
    assert "kyle" in recent and "shaz" not in recent


@pytest.mark.asyncio
async def test_audit_cap_prunes(tmp_path) -> None:
    s = SqlitePolicyStore(
        str(tmp_path / "p.db"), parent_issuer="rd-cabal",
        audit_max_rows=5, audit_prune_interval=1,
    )
    try:
        for i in range(30):
            await s.record_access(
                issuer="shaz", persona="rook", agent=None, allowed=False, detail={"i": i}
            )
        rows = await s.audit(limit=100)
        assert len(rows) == 5  # bounded to the most recent audit_max_rows
    finally:
        s.close()


def test_parent_reseed_is_idempotent(tmp_path) -> None:
    path = str(tmp_path / "p.db")
    s1 = SqlitePolicyStore(path, parent_issuer="rd-cabal")
    s1.close()
    # Reopening with the same parent must not duplicate the parent row.
    s2 = SqlitePolicyStore(path, parent_issuer="rd-cabal")
    try:
        assert s2.parents() == frozenset({"rd-cabal"})
    finally:
        s2.close()
