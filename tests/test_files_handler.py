"""files handler — allowlist + traversal defense + read/write/list/exists."""

from __future__ import annotations

import os
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



class _ReadSpy:
    """Wraps an open file and records every read() size it is asked for."""

    def __init__(self, fh: Any, sizes: list[int]) -> None:
        self._fh = fh
        self._sizes = sizes

    def read(self, size: int = -1) -> bytes:
        self._sizes.append(size)
        return self._fh.read(size)

    def __enter__(self) -> _ReadSpy:
        return self

    def __exit__(self, *exc: object) -> None:
        self._fh.close()


@pytest.mark.asyncio
async def test_read_of_a_file_over_the_cap_reads_only_cap_plus_one(
    tmp_path, monkeypatch
) -> None:
    """#194: a file far larger than the cap is never loaded whole."""
    target = tmp_path / "huge.log"
    target.write_bytes(b"z" * 200_000)
    sizes: list[int] = []
    real_open = Path.open

    def spy_open(self: Path, *args: Any, **kwargs: Any) -> _ReadSpy:
        return _ReadSpy(real_open(self, *args, **kwargs), sizes)

    def no_read_bytes(self: Path) -> bytes:
        raise AssertionError("read_bytes loads the whole file")

    monkeypatch.setattr(Path, "open", spy_open)
    monkeypatch.setattr(Path, "read_bytes", no_read_bytes)
    handler = _build_handler([tmp_path], max_read_bytes=100)
    result = await handler.dispatch("read", {"path": str(target)}, _ctx())
    assert result.is_error is False, result.error
    payload = result.content[0]["data"]
    assert payload["bytes"] == 100
    assert payload["truncated"] is True
    assert sizes == [101]


@pytest.mark.asyncio
async def test_read_of_a_file_exactly_at_the_cap_is_not_truncated(tmp_path) -> None:
    target = tmp_path / "exact.txt"
    target.write_bytes(b"e" * 100)
    handler = _build_handler([tmp_path], max_read_bytes=100)
    result = await handler.dispatch("read", {"path": str(target)}, _ctx())
    payload = result.content[0]["data"]
    assert payload["bytes"] == 100
    assert payload["truncated"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("max_bytes", [-5, 0])
async def test_max_bytes_below_one_clamps_to_one(tmp_path, max_bytes: int) -> None:
    """#194: -5 used to slice the tail off and still say truncated."""
    target = tmp_path / "abc.txt"
    target.write_text("abcdef")
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "read", {"path": str(target), "max_bytes": max_bytes}, _ctx()
    )
    assert result.is_error is False, result.error
    payload = result.content[0]["data"]
    assert payload["text"] == "a"
    assert payload["bytes"] == 1
    assert payload["truncated"] is True


@pytest.mark.asyncio
async def test_max_bytes_within_range_is_honoured(tmp_path) -> None:
    target = tmp_path / "abc.txt"
    target.write_text("abcdef")
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "read", {"path": str(target), "max_bytes": 3}, _ctx()
    )
    payload = result.content[0]["data"]
    assert payload["text"] == "abc"
    assert payload["truncated"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("max_bytes", ["abc", "10", 1.5, True, [10]])
async def test_non_integer_max_bytes_is_refused_naming_the_field(
    tmp_path, max_bytes: Any
) -> None:
    target = tmp_path / "abc.txt"
    target.write_text("abcdef")
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "read", {"path": str(target), "max_bytes": max_bytes}, _ctx()
    )
    assert result.is_error is True
    assert "'max_bytes' must be an integer" in result.error


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



@pytest.mark.asyncio
@pytest.mark.parametrize("create_parents", ["false", 0, None])
async def test_non_boolean_create_parents_is_refused_naming_the_field(
    tmp_path, create_parents: Any
) -> None:
    """#193: bool("false") is True, so the string used to create the parents."""
    target = tmp_path / "new" / "out.txt"
    handler = _build_handler([tmp_path])
    result = await handler.dispatch(
        "write",
        {"path": str(target), "content": "x", "create_parents": create_parents},
        _ctx(),
    )
    assert result.is_error is True
    assert "'create_parents' must be a boolean" in result.error
    assert not target.parent.exists()


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
async def test_list_is_sorted_by_name(tmp_path) -> None:
    for name in ["c", "a", "e", "b", "d"]:
        (tmp_path / name).write_text(name)
    handler = _build_handler([tmp_path])
    result = await handler.dispatch("list", {"path": str(tmp_path)}, _ctx())
    payload = result.content[0]["data"]
    assert [e["name"] for e in payload["entries"]] == ["a", "b", "c", "d", "e"]
    assert payload["truncated"] is False


@pytest.mark.asyncio
async def test_list_of_a_large_directory_stops_at_the_cap(
    tmp_path, monkeypatch
) -> None:
    """#194: the scan pulls cap + 1 entries, not the whole directory."""
    for i in range(2000):
        (tmp_path / f"f{i:04d}").touch()
    pulled = 0
    real_scandir = os.scandir

    class _CountingScandir:
        def __init__(self, path: Any) -> None:
            self._it = real_scandir(path)

        def __enter__(self) -> _CountingScandir:
            return self

        def __exit__(self, *exc: object) -> None:
            self._it.close()

        def __iter__(self) -> _CountingScandir:
            return self

        def __next__(self) -> os.DirEntry[str]:
            nonlocal pulled
            entry = next(self._it)
            pulled += 1
            return entry

    monkeypatch.setattr(os, "scandir", _CountingScandir)
    handler = _build_handler([tmp_path], max_list_entries=10)
    result = await handler.dispatch("list", {"path": str(tmp_path)}, _ctx())
    payload = result.content[0]["data"]
    assert len(payload["entries"]) == 10
    assert payload["truncated"] is True
    names = [e["name"] for e in payload["entries"]]
    assert names == sorted(names)
    assert pulled == 11


@pytest.mark.asyncio
async def test_list_skips_a_dangling_symlink(tmp_path) -> None:
    (tmp_path / "real").write_text("x")
    (tmp_path / "dangling").symlink_to(tmp_path / "missing")
    handler = _build_handler([tmp_path])
    result = await handler.dispatch("list", {"path": str(tmp_path)}, _ctx())
    payload = result.content[0]["data"]
    assert [e["name"] for e in payload["entries"]] == ["real"]


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


# ---- operator allowlist from the environment (#68) -----------------------


def _fresh_handler(monkeypatch, value: str | None):
    """get_handler() memoises, so reset the singleton before each read."""
    import liminal.handlers.files as files_mod

    monkeypatch.setattr(files_mod, "_SINGLETON", None)
    if value is None:
        monkeypatch.delenv(files_mod.ALLOWED_PATHS_ENV, raising=False)
    else:
        monkeypatch.setenv(files_mod.ALLOWED_PATHS_ENV, value)
    return files_mod.get_handler()


@pytest.mark.anyio
async def test_unset_env_still_refuses_everything(monkeypatch, tmp_path) -> None:
    """The fail-closed default is the whole point and must not have moved.

    Asserting the empty list is not enough — the name promises a refusal, so the
    test performs one (review of #100, nit 4).
    """
    target = tmp_path / "f.txt"
    target.write_text("x")

    handler = _fresh_handler(monkeypatch, None)
    assert handler.default_config.allowed_paths == []

    result = await handler.dispatch("read", {"path": str(target)}, _ctx(extra={}))
    assert result.is_error is True


@pytest.mark.anyio
async def test_an_empty_claim_grants_nothing_rather_than_the_ceiling(
    monkeypatch, tmp_path
) -> None:
    """A persona that says "no paths" must not inherit the operator ceiling.

    THE BUG THIS PINS (found reviewing #100): `_resolve_config` fell back to
    `default_config` whenever the claim was falsy. That was safe only while the
    default was always empty. With an env-supplied ceiling it meant a claim of
    `[]` — an explicit grant of nothing — silently became the whole ceiling.
    """
    target = tmp_path / "s.txt"
    target.write_text("secret")

    handler = _fresh_handler(monkeypatch, str(tmp_path))

    for claim in ([], [""], "/nowhere", {"not": "a list"}, [None]):
        result = await handler.dispatch(
            "read", {"path": str(target)}, _ctx(extra={"files.allowed_paths": claim})
        )
        assert result.is_error is True, f"claim {claim!r} was granted the ceiling"

    # An ABSENT key is the documented fallback and still reaches the ceiling.
    ok = await handler.dispatch("read", {"path": str(target)}, _ctx(extra={}))
    assert ok.is_error is False

    # And a key absent from a non-empty extras dict is still absent.
    ok2 = await handler.dispatch(
        "read", {"path": str(target)}, _ctx(extra={"memory.db_path": "/x"})
    )
    assert ok2.is_error is False


def test_a_relative_ceiling_segment_is_refused(monkeypatch, tmp_path) -> None:
    """`.` as a ceiling would grant wherever the daemon happened to start."""
    handler = _fresh_handler(monkeypatch, f".{os.pathsep}{tmp_path}{os.pathsep}  ")
    assert handler.default_config.allowed_paths == [tmp_path.resolve()]


def test_env_seeds_the_operator_allowlist(monkeypatch, tmp_path) -> None:
    """LIMINAL_FILES_ALLOWED_PATHS is the supported opt-in without a JWT."""
    handler = _fresh_handler(monkeypatch, str(tmp_path))
    assert handler.default_config.allowed_paths == [tmp_path.resolve()]


def test_env_accepts_several_paths_and_ignores_empty_segments(monkeypatch, tmp_path) -> None:
    import os

    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    raw = os.pathsep.join([str(a), "", str(b), "  "])
    handler = _fresh_handler(monkeypatch, raw)
    assert handler.default_config.allowed_paths == [a.resolve(), b.resolve()]


@pytest.mark.anyio
async def test_env_allowlist_grants_a_read_with_no_jwt_claims(monkeypatch, tmp_path) -> None:
    """The #68 case end to end: auth-off, ctx.extra empty, read succeeds."""
    target = tmp_path / "hello.txt"
    target.write_text("reachable")

    handler = _fresh_handler(monkeypatch, str(tmp_path))
    result = await handler.dispatch("read", {"path": str(target)}, _ctx(extra={}))

    assert result.is_error is False
    assert "reachable" in str(result.content)


@pytest.mark.anyio
async def test_env_allowlist_is_a_ceiling_not_a_grant(monkeypatch, tmp_path) -> None:
    """A path outside the env allowlist stays refused, ctx.extra or not."""
    inside = tmp_path / "in"
    inside.mkdir()
    outside = tmp_path / "out"
    outside.mkdir()
    victim = outside / "secret.txt"
    victim.write_text("nope")

    handler = _fresh_handler(monkeypatch, str(inside))

    r1 = await handler.dispatch("read", {"path": str(victim)}, _ctx(extra={}))
    assert r1.is_error is True

    # A persona claim cannot widen past the operator ceiling either.
    r2 = await handler.dispatch(
        "read", {"path": str(victim)}, _ctx(extra={"files.allowed_paths": [str(outside)]})
    )
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
