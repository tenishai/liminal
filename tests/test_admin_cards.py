"""GET /admin/cards: the loaded handlers' capability cards on the admin plane.

A governing service (a room that grants per persona) derives what a grant opens
from what each handler declares: its vendor on the card's `labels`, and on each
tool the permissions that open it and its risk. Those are fields the card schema
allows but does not name, so the route must hand them back as written.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from liminal.handlers.scratchpad import ScratchpadHandler
from liminal.protocol.tool import ToolResult, ToolSpec
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import SqlitePolicyStore, create_admin_app, create_app

from .test_live_targets import _verifier
from .test_policy_inversion import _hdr, _key, _mint


class _Labelled:
    """A handler whose card carries the fields a room reads."""

    def tools(self) -> list[ToolSpec]:
        return [ToolSpec(name="lookup", description="d", input_schema={"type": "object"})]

    def capability_card(self) -> dict[str, Any]:
        return {
            "handler": "vendorx",
            "description": "vendor x",
            "required_scope": "vendorx:read",
            "labels": {"vendor": "vendorx"},
            "tools": [
                {"name": "lookup", "description": "d", "permissions": ["vendorx_read"], "risk": "low"},
                {"name": "change", "description": "d", "required_scope": "vendorx:write",
                 "permissions": ["vendorx_write"], "risk": "write"},
            ],
        }

    async def dispatch(self, name: str, payload: dict[str, Any], ctx) -> ToolResult:
        return ToolResult(content=[{"type": "text", "text": "ok"}])


def _registry() -> Registry:
    reg = Registry()
    register_explicit(reg, "vendorx", _Labelled())
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    return reg


@pytest.mark.asyncio
async def test_cards_come_back_by_name_with_the_fields_a_handler_adds(tmp_path) -> None:
    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "policy.db"), parent_issuer="rd-cabal")
    reg = _registry()
    verifier = _verifier(kp, ks)
    data = create_app(jwt_verifier=verifier, registry=reg, policy_store=store, mount_admin=False)
    admin = create_admin_app(jwt_verifier=verifier, policy_store=store, registry=reg)
    async with data.router.lifespan_context(data):
        async with AsyncClient(transport=ASGITransport(app=admin), base_url="http://admin") as a:
            assert (await a.get("/admin/cards")).status_code == 401
            third = _mint(ks, iss="shaz-cabal")
            assert (await a.get("/admin/cards", headers=_hdr(third))).status_code == 403
            parent = _mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")
            r = await a.get("/admin/cards", headers=_hdr(parent))
    store.close()
    assert r.status_code == 200, r.text
    cards = r.json()["cards"]
    assert [c["name"] for c in cards] == ["scratchpad", "vendorx"]
    card = cards[1]["card"]
    assert card["labels"] == {"vendor": "vendorx"} and card["required_scope"] == "vendorx:read"
    lookup, change = card["tools"]
    assert lookup["permissions"] == ["vendorx_read"] and lookup["risk"] == "low"
    assert change["required_scope"] == "vendorx:write" and change["risk"] == "write"


@pytest.mark.asyncio
async def test_an_admin_plane_without_the_registry_says_so_instead_of_listing_nothing(tmp_path) -> None:
    kp, ks = _key(), _key()
    store = SqlitePolicyStore(str(tmp_path / "policy.db"), parent_issuer="rd-cabal")
    admin = create_admin_app(jwt_verifier=_verifier(kp, ks), policy_store=store)
    async with AsyncClient(transport=ASGITransport(app=admin), base_url="http://admin") as a:
        r = await a.get("/admin/cards", headers=_hdr(_mint(kp, iss="rd-cabal", persona="ops", sub="ops-1")))
    store.close()
    assert r.status_code == 404 and "registry" in r.json()["detail"]
