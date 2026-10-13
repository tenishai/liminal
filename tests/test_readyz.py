"""``/readyz`` (liminal#159): the ``/healthz`` body, but 503 while any target is
degraded, so a readiness probe takes a gateway with a dead upstream out of
service. ``/healthz`` stays 200 for liveness."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from liminal.handlers.scratchpad import ScratchpadHandler
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import create_app


def _app():
    reg = Registry()
    register_explicit(reg, "scratchpad", ScratchpadHandler())
    return create_app(registry=reg)


class _Broken:
    name = "vendor"
    catalog_status = "catalog fetch failed (startup)"


@pytest.mark.asyncio
async def test_readyz_is_503_while_degraded_and_healthz_stays_200():
    app = _app()
    app.state.dispatcher._targets["vendor"] = _Broken()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        ready, health = await c.get("/readyz"), await c.get("/healthz")
    assert ready.status_code == 503
    assert health.status_code == 200
    assert ready.json() == health.json()
    assert ready.json()["status"] == "degraded"


@pytest.mark.asyncio
async def test_readyz_is_200_when_every_target_is_ready():
    app = _app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/readyz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "targets": {"scratchpad": "ready"}}
