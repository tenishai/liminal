"""files handler — allowlist + traversal defense + read/write/list/exists."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from liminal.handlers.files import FilesConfig, FilesHandler
from liminal.protocol import Context


def _ctx(extra: dict[str, Any] | None = None) -> Context:
    return Context(
        identity="rook",
        agent_name="rook-primus",
        credentials={},
        extra=extra or {},
    )


def _build_handler(
    allowed: list[Path] | None = None,
    *,
    max_read_bytes: int = 1_000_000,
    max_write_bytes: int = 500_000,
    max_list_entries: int = 500,
) -> FilesHandler:
    cfg = FilesConfig(
        allowed_paths=allowed or [],
        max_read_bytes=max_read_bytes,
        max_write_bytes=max_write_bytes,
        max_list_entries=max_list_entries,
    )
    return FilesHandler(default_config=cfg)


# ---- safety / pre-flight refusals ----------------------------------------


@pytest.mark.asyncio
async def test_default_handler_refuses_with_no_allowlist(tmp_path) -> None:
    """Fresh handler with NO allowed paths should refuse any operation."""
    handler = _build_handler()  # empty allowlist
    result = await handler.dispatch(
        "read", {"path": str(tmp_path / "x")}, _ctx()
    )
    assert result.is_error is True
    assert "no allowlist" in result.error


@pytest.mark.asyncio
async def test_relative_path_refused(tmp_path) -> None:
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "read", {"path": "relative/path.txt"}, _ctx()
    )
    assert result.is_error is True
    assert "absolute" in result.error


@pytest.mark.asyncio
async def test_double_dot_segment_refused(tmp_path) -> None:
    """`..` in any path segment is refused as defense-in-depth, even
    though resolve() would catch the escape too."""
    handler = _build_handler([tmp_path])
    target = f"{tmp_path}/../escape.txt"
    result = await handler.dispatch("read", {"path": target}, _ctx())
    assert result.is_error is True
    assert ".." in result.error


@pytest.mark.asyncio
async def test_absolute_outside_allowlist_refused(tmp_path) -> None:
    handler = _build_handler([tmp_path])
    elsewhere = tmp_path.parent / "elsewhere.txt"
    result = await handler.dispatch(
        "read", {"path": str(elsewhere)}, _ctx()
    )
    assert result.is_error is True
    assert "not under any allowlisted prefix" in result.error


@pytest.mark.asyncio
async def test_symlink_escape_refused(tmp_path) -> None:
    """A symlink inside the allowlist that targets a path outside is
    refused — resolve() follows the symlink, and the escape is detected."""
    inside = tmp_path / "ok"
    outside = tmp_path.parent / "exfiltrate.txt"
    outside.write_text("secret")
    inside.symlink_to(outside)

    handler = _build_handler([tmp_path])
    result = await handler.dispatch("read", {"path": str(inside)}, _ctx())
    assert result.is_error is True


@pytest.mark.asyncio
async def test_empty_path_refused() -> None:
    handler = _build_handler([Path("/tmp")])
    result = await handler.dispatch("read", {"path": ""}, _ctx())
    assert result.is_error is True


# ---- read ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_returns_text(tmp_path) -> None:
    target = tmp_path / "hello.txt"
    target.write_text("Hello, files!")
    handler = _build_handler([tmp_path])
    result = await handler.dispatch("read", {"path": str(target)}, _ctx())
    assert result.is_error is False
    payload = result.content[0]["data"]
    assert payload["text"] == "Hello, files!"
    assert payload["bytes"] == 13
    assert payload["truncated"] is False


@pytest.mark.asyncio
async def test_read_missing_file_errors(tmp_path) -> None:
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "read", {"path": str(tmp_path / "nope")}, _ctx()
    )
    assert result.is_error is True
    assert "no such file" in result.error


@pytest.mark.asyncio
async def test_read_directory_errors(tmp_path) -> None:
    handler = _build_handler([tmp_path])
    result = await handler.dispatch("read", {"path": str(tmp_path)}, _ctx())
    assert result.is_error is True
    assert "not a file" in result.error


@pytest.mark.asyncio
async def test_read_truncates_at_size_cap(tmp_path) -> None:
    target = tmp_path / "big.txt"
    target.write_text("x" * 5000)
    handler = _build_handler([tmp_path], max_read_bytes=1024)
    result = await handler.dispatch("read", {"path": str(target)}, _ctx())
    payload = result.content[0]["data"]
    assert payload["bytes"] == 1024
    assert payload["truncated"] is True


@pytest.mark.asyncio
async def test_caller_max_bytes_is_capped_by_handler_config(tmp_path) -> None:
    target = tmp_path / "big.txt"
    target.write_text("y" * 5000)
    handler = _build_handler([tmp_path], max_read_bytes=2000)
    # Caller asks for 99999 — handler still caps at its 2000
    result = await handler.dispatch(
        "read", {"path": str(target), "max_bytes": 99999}, _ctx()
    )
    payload = result.content[0]["data"]
    assert payload["bytes"] == 2000


# ---- write -------------------------------------------------------------


@pytest.mark.asyncio
async def test_write_creates_file(tmp_path) -> None:
    target = tmp_path / "out.txt"
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "write", {"path": str(target), "content": "wrote me"}, _ctx()
    )
    assert result.is_error is False
    assert target.read_text() == "wrote me"
    payload = result.content[0]["data"]
    assert payload["bytes_written"] == 8


@pytest.mark.asyncio
async def test_write_creates_parents_by_default(tmp_path) -> None:
    target = tmp_path / "nested" / "subdir" / "file.txt"
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "write", {"path": str(target), "content": "x"}, _ctx()
    )
    assert result.is_error is False
    assert target.exists()


@pytest.mark.asyncio
async def test_write_create_parents_false_fails_for_missing(tmp_path) -> None:
    target = tmp_path / "absent" / "file.txt"
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "write",
        {"path": str(target), "content": "x", "create_parents": False},
        _ctx(),
    )
    assert result.is_error is True


@pytest.mark.asyncio
async def test_write_rejects_oversized_payload(tmp_path) -> None:
    target = tmp_path / "huge.txt"
    handler = _build_handler([tmp_path], max_write_bytes=100)
    result = await handler.dispatch(
        "write", {"path": str(target), "content": "y" * 500}, _ctx()
    )
    assert result.is_error is True
    assert "max_write_bytes" in result.error
    assert not target.exists()


@pytest.mark.asyncio
async def test_write_outside_allowlist_refused(tmp_path) -> None:
    """Same allowlist enforcement as read — write doesn't get a backdoor."""
    handler = _build_handler([tmp_path])
    escape = tmp_path.parent / "escape.txt"
    result = await handler.dispatch(
        "write", {"path": str(escape), "content": "leak"}, _ctx()
    )
    assert result.is_error is True
    assert not escape.exists()


@pytest.mark.asyncio
async def test_write_content_must_be_string(tmp_path) -> None:
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "write",
        {"path": str(tmp_path / "x.txt"), "content": {"not": "a string"}},
        _ctx(),
    )
    assert result.is_error is True
    assert "'content'" in result.error


# ---- list -------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_returns_entries(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("bb")
    (tmp_path / "subdir").mkdir()
    handler = _build_handler([tmp_path])
    result = await handler.dispatch("list", {"path": str(tmp_path)}, _ctx())
    payload = result.content[0]["data"]
    by_name = {e["name"]: e for e in payload["entries"]}
    assert set(by_name.keys()) == {"a.txt", "b.txt", "subdir"}
    assert by_name["a.txt"]["type"] == "file"
    assert by_name["a.txt"]["size"] == 1
    assert by_name["subdir"]["type"] == "dir"
    assert by_name["subdir"]["size"] is None


@pytest.mark.asyncio
async def test_list_truncates_at_cap(tmp_path) -> None:
    for i in range(15):
        (tmp_path / f"file-{i:02d}").write_text("x")
    handler = _build_handler([tmp_path], max_list_entries=5)
    result = await handler.dispatch("list", {"path": str(tmp_path)}, _ctx())
    payload = result.content[0]["data"]
    assert len(payload["entries"]) == 5
    assert payload["truncated"] is True


@pytest.mark.asyncio
async def test_list_missing_directory_errors(tmp_path) -> None:
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "list", {"path": str(tmp_path / "ghost")}, _ctx()
    )
    assert result.is_error is True


@pytest.mark.asyncio
async def test_list_on_file_errors(tmp_path) -> None:
    target = tmp_path / "f.txt"
    target.write_text("x")
    handler = _build_handler([tmp_path])
    result = await handler.dispatch("list", {"path": str(target)}, _ctx())
    assert result.is_error is True
    assert "not a directory" in result.error


# ---- exists -----------------------------------------------------------


@pytest.mark.asyncio
async def test_exists_true_and_false(tmp_path) -> None:
    target = tmp_path / "f.txt"
    target.write_text("x")
    handler = _build_handler([tmp_path])

    r1 = await handler.dispatch("exists", {"path": str(target)}, _ctx())
    assert r1.content[0]["data"]["exists"] is True

    r2 = await handler.dispatch(
        "exists", {"path": str(tmp_path / "absent")}, _ctx()
    )
    assert r2.content[0]["data"]["exists"] is False


@pytest.mark.asyncio
async def test_exists_for_directory(tmp_path) -> None:
    handler = _build_handler([tmp_path])
    result = await handler.dispatch("exists", {"path": str(tmp_path)}, _ctx())
    assert result.content[0]["data"]["exists"] is True


# ---- per-persona allowlist override -----------------------------------


@pytest.mark.asyncio
async def test_per_persona_allowlist_via_ctx_extra(tmp_path) -> None:
    """ctx.extra["files.allowed_paths"] tightens or replaces the default."""
    persona_only = tmp_path / "persona-scope"
    persona_only.mkdir()
    target = persona_only / "file.txt"
    target.write_text("persona reach")

    handler = _build_handler([tmp_path])  # default allows tmp_path broadly
    ctx = _ctx(extra={"files.allowed_paths": [str(persona_only)]})

    # In scope
    r1 = await handler.dispatch("read", {"path": str(target)}, ctx)
    assert r1.is_error is False

    # Out of scope (still under default but not under persona override)
    other = tmp_path / "other.txt"
    other.write_text("nope")
    r2 = await handler.dispatch("read", {"path": str(other)}, ctx)
    assert r2.is_error is True


# ---- entry-point + card --------------------------------------------------


def test_handler_is_registered_in_entry_points() -> None:
    from liminal.registry import discover_handlers

    registry = discover_handlers()
    record = registry.get("files")
    assert record is not None
    assert record.card.handler == "files"
    tool_names = {t.name for t in record.card.tools}
    assert tool_names == {"read", "write", "list", "exists"}


def test_capability_card_requires_no_credentials() -> None:
    from liminal.handlers.files import get_handler

    card = get_handler().capability_card()
    assert card["credential_keys"] == []
