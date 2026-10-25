"""memory handler — techne-backed recall + commit.

The module-scope `pytest.importorskip("techne")` below skips the whole
module when techne is not installed. Install it from the
requirements-sources.txt pin or as an editable sibling checkout (see
README). Tests that touch the backend run it against a tmp_path SQLite DB.
"""
from __future__ import annotations

import sys

import pytest

pytest.importorskip("techne")
from pathlib import Path
from typing import Any

import pytest

from liminal.handlers.memory import (
    MemoryConfig,
    MemoryHandler,
    _sanitize_query,
)
from liminal.protocol import Context


def _ctx(extra: dict[str, Any] | None = None) -> Context:
    return Context(
        identity="rook",
        agent_name="rook-primus",
        credentials={},
        extra=extra or {},
    )


@pytest.fixture
def techne_db(tmp_path: Path) -> Path:
    """A freshly-initialized techne SQLite DB."""
    import techne

    db = tmp_path / "memory.db"
    techne.init_db(db)
    return db


def _handler(db: Path | None) -> MemoryHandler:
    return MemoryHandler(default_config=MemoryConfig(db_path=db))


# ---- query sanitizer (mirrors Cabal's pattern) ---------------------------


def test_sanitize_strips_stopwords_and_or_joins() -> None:
    assert _sanitize_query("what is the answer") == "answer"
    # Multi-token natural query → OR'd
    assert _sanitize_query("favorite color memory") == "favorite OR color OR memory"


def test_sanitize_strips_fts5_specials() -> None:
    """Punctuation FTS5 treats as operators — ?, ", *, NEAR — gets stripped."""
    assert "?" not in _sanitize_query("what is the answer?")
    assert "*" not in _sanitize_query("wild*card")


def test_sanitize_returns_empty_on_all_stopwords() -> None:
    assert _sanitize_query("what is the") == ""
    assert _sanitize_query("???") == ""


def test_sanitize_lowercases() -> None:
    assert _sanitize_query("Operator Neovim") == "operator OR neovim"


# ---- pre-flight refusals --------------------------------------------------


@pytest.mark.asyncio
async def test_no_db_path_configured_refuses() -> None:
    handler = _handler(None)
    result = await handler.dispatch("recall", {"query": "anything"}, _ctx())
    assert result.is_error is True
    assert "no memory DB" in result.error


@pytest.mark.asyncio
async def test_recall_requires_non_empty_query(techne_db) -> None:
    handler = _handler(techne_db)
    r1 = await handler.dispatch("recall", {"query": ""}, _ctx())
    r2 = await handler.dispatch("recall", {}, _ctx())
    r3 = await handler.dispatch("recall", {"query": "    "}, _ctx())
    for r in (r1, r2, r3):
        assert r.is_error is True


@pytest.mark.asyncio
async def test_recall_all_stopwords_returns_empty_hits(techne_db) -> None:
    """A query that sanitizes to empty should return zero hits, not error."""
    handler = _handler(techne_db)
    result = await handler.dispatch("recall", {"query": "what is the"}, _ctx())
    assert result.is_error is False
    assert result.content[0]["data"]["hits"] == []


@pytest.mark.asyncio
async def test_commit_requires_non_empty_content(techne_db) -> None:
    handler = _handler(techne_db)
    result = await handler.dispatch(
        "commit", {"content": "  "}, _ctx()
    )
    assert result.is_error is True


@pytest.mark.asyncio
async def test_commit_rejects_invalid_type(techne_db) -> None:
    handler = _handler(techne_db)
    result = await handler.dispatch(
        "commit", {"content": "x", "type": "wisdom"}, _ctx()
    )
    assert result.is_error is True
    assert "fact" in result.error  # one of the valid choices listed


@pytest.mark.asyncio
async def test_commit_rejects_invalid_confidence(techne_db) -> None:
    handler = _handler(techne_db)
    result = await handler.dispatch(
        "commit",
        {"content": "x", "confidence": "very-high"},
        _ctx(),
    )
    assert result.is_error is True
    assert "low" in result.error  # one of the valid choices listed


@pytest.mark.asyncio
async def test_commit_rejects_non_string_tags(techne_db) -> None:
    handler = _handler(techne_db)
    result = await handler.dispatch(
        "commit", {"content": "x", "tags": ["not", "a", "string"]}, _ctx()
    )
    assert result.is_error is True



@pytest.mark.asyncio
@pytest.mark.parametrize("limit", ["abc", "10", 2.5, True])
async def test_recall_rejects_non_integer_limit_naming_the_field(
    techne_db, limit: Any
) -> None:
    """#193: int("abc") used to raise and reach the agent as a bare class name."""
    handler = _handler(techne_db)
    result = await handler.dispatch(
        "recall", {"query": "sky", "limit": limit}, _ctx()
    )
    assert result.is_error is True
    assert "'limit' must be an integer" in result.error


@pytest.mark.asyncio
async def test_recall_null_limit_uses_the_default(techne_db) -> None:
    handler = _handler(techne_db)
    result = await handler.dispatch(
        "recall", {"query": "sky", "limit": None}, _ctx()
    )
    assert result.is_error is False, result.error


# ---- happy path ----------------------------------------------------------


@pytest.mark.asyncio
async def test_commit_then_recall_roundtrip(techne_db) -> None:
    handler = _handler(techne_db)

    r1 = await handler.dispatch(
        "commit",
        {
            "content": "Operator prefers Neovim for editing",
            "type": "fact",
            "tags": "preferences",
            "confidence": "high",
        },
        _ctx(),
    )
    assert r1.is_error is False
    assert r1.content[0]["data"]["committed"] is True

    # FTS5 default tokenizer doesn't stem — match on a word actually in
    # the stored content.
    r2 = await handler.dispatch(
        "recall", {"query": "what does operator prefer?"}, _ctx()
    )
    assert r2.is_error is False
    hits = r2.content[0]["data"]["hits"]
    assert any("Neovim" in h["content"] for h in hits)


@pytest.mark.asyncio
async def test_recall_limit_clamped(techne_db) -> None:
    """A caller asking for limit=999 should be capped at 50."""
    handler = _handler(techne_db)
    # Seed a few entries
    for i in range(8):
        await handler.dispatch(
            "commit",
            {"content": f"sky-note-{i}", "type": "fact", "tags": "sky"},
            _ctx(),
        )
    result = await handler.dispatch(
        "recall", {"query": "sky", "limit": 999}, _ctx()
    )
    # techne's actual cap is 50 from the handler clamp
    assert len(result.content[0]["data"]["hits"]) <= 50


@pytest.mark.asyncio
async def test_commit_initializes_missing_db(tmp_path) -> None:
    """A handler pointed at a DB path that doesn't exist should bootstrap
    it on first commit rather than erroring."""
    db = tmp_path / "fresh" / "memory.db"
    assert not db.exists()
    handler = _handler(db)
    result = await handler.dispatch(
        "commit", {"content": "bootstrap test", "type": "fact"}, _ctx()
    )
    assert result.is_error is False
    assert db.exists()


# ---- per-persona DB override ---------------------------------------------


@pytest.mark.asyncio
async def test_per_persona_db_path_via_ctx_extra(tmp_path) -> None:
    import techne

    persona_db = tmp_path / "rook-only.db"
    techne.init_db(persona_db)
    # Configure allowed_db_dirs so the JWT override is accepted.
    handler = MemoryHandler(
        default_config=MemoryConfig(db_path=None, allowed_db_dirs=[tmp_path])
    )

    ctx = _ctx(extra={"memory.db_path": str(persona_db)})
    result = await handler.dispatch(
        "commit",
        {"content": "persona-scoped knowledge", "type": "fact"},
        ctx,
    )
    assert result.is_error is False
    # The default-db handler still has no DB
    r2 = await handler.dispatch("recall", {"query": "persona"}, _ctx())
    assert r2.is_error is True  # falls through to "no DB"


# ---- techne-not-installed path ------------------------------------------


@pytest.mark.asyncio
async def test_missing_techne_returns_structured_error(techne_db, monkeypatch) -> None:
    """If techne isn't importable the handler should NOT crash — it should
    return a structured error the LLM can read."""

    # Force the lazy import to fail by ejecting techne from sys.modules and
    # blocking the import.
    monkeypatch.setitem(sys.modules, "techne", None)

    handler = _handler(techne_db)
    result = await handler.dispatch("recall", {"query": "anything"}, _ctx())
    assert result.is_error is True
    assert "techne" in result.error


# ---- entry-point + card -------------------------------------------------


def test_handler_registered_in_entry_points() -> None:
    from liminal.registry import discover_handlers

    registry = discover_handlers()
    record = registry.get("memory")
    assert record is not None
    assert record.card.handler == "memory"
    assert {t.name for t in record.card.tools} == {"recall", "commit"}


def test_capability_card_requires_no_credentials() -> None:
    from liminal.handlers.memory import get_handler

    card = get_handler().capability_card()
    assert card["credential_keys"] == []
    assert card["labels"]["backend"] == "techne"


def test_get_handler_reads_env_db_path(monkeypatch, tmp_path) -> None:
    """LIMINAL_MEMORY_DB seeds default_config.db_path; unset/empty → None.

    The singleton is read once per process, so reset it before each call so the
    env var is actually re-consulted (the ordering trap Prudence flagged).
    """
    import liminal.handlers.memory as mem

    # env set → path populated (expanduser applied)
    monkeypatch.setattr(mem, "_SINGLETON", None)
    db = tmp_path / "techne.db"
    monkeypatch.setenv("LIMINAL_MEMORY_DB", str(db))
    assert mem.get_handler().default_config.db_path == db

    # empty string is falsy → no db_path
    monkeypatch.setattr(mem, "_SINGLETON", None)
    monkeypatch.setenv("LIMINAL_MEMORY_DB", "")
    assert mem.get_handler().default_config.db_path is None

    # unset → None
    monkeypatch.setattr(mem, "_SINGLETON", None)
    monkeypatch.delenv("LIMINAL_MEMORY_DB", raising=False)
    assert mem.get_handler().default_config.db_path is None
