"""Unconfigured handlers say so on /healthz instead of "ready" (liminal#191)."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from liminal.handlers.files import FilesConfig, FilesHandler
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import create_app


async def _health(handler, monkeypatch) -> dict:
    monkeypatch.setenv("LIMINAL_AUTH_DISABLED", "1")
    reg = Registry()
    register_explicit(reg, "files", handler)
    app = create_app(registry=reg)
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            health = (await c.get("/healthz")).json()
            ready = (await c.get("/readyz")).status_code
    return {**health, "readyz": ready}


@pytest.mark.asyncio
async def test_files_without_an_allowlist_reads_unconfigured_but_not_degraded(monkeypatch):
    body = await _health(FilesHandler(), monkeypatch)
    assert body["targets"]["files"].startswith("unconfigured: LIMINAL_FILES_ALLOWED_PATHS")
    assert body["status"] == "ok"
    assert body["readyz"] == 200


@pytest.mark.asyncio
async def test_files_with_an_allowlist_reads_ready(monkeypatch, tmp_path: Path):
    handler = FilesHandler(default_config=FilesConfig(allowed_paths=[tmp_path]))
    body = await _health(handler, monkeypatch)
    assert body["targets"]["files"] == "ready"


def test_memory_without_a_db_says_unconfigured():
    from liminal.handlers.memory import MemoryConfig, MemoryHandler

    assert MemoryHandler().status() == (
        "unconfigured: LIMINAL_MEMORY_DB is unset, so every call is refused"
    )
    with_dirs = MemoryHandler(default_config=MemoryConfig(allowed_db_dirs=[Path("/srv/m")]))
    assert "only a per-caller memory.db_path under /srv/m" in with_dirs.status()
    assert MemoryHandler(default_config=MemoryConfig(db_path=Path("/x.db"))).status() is None


def test_a_handler_without_status_is_ready():
    from liminal.handlers.scratchpad import ScratchpadHandler
    from liminal.target.inprocess import InProcessTarget

    assert InProcessTarget("scratchpad", ScratchpadHandler()).config_status is None


def test_a_status_that_raises_does_not_break_the_probe():
    from liminal.target.inprocess import InProcessTarget

    class Broken:
        def tools(self):
            return []

        def status(self):
            raise RuntimeError("boom")

    assert InProcessTarget("x", Broken()).config_status == "status() failed: RuntimeError"
