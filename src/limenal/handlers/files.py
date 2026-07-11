"""files — scoped file I/O with path-traversal defense.

Per design.md §"Planned handlers":

    files | Scoped file I/O. Each persona's identity.toml declares a
    files.paths allowlist (e.g., ["~/projects/cabal",
    "~/.cbl/scratch/rook"]); reads and writes outside the allowlist
    return a structured error. Path traversal (..) is rejected before
    the allowlist check.

Defenses (applied before any disk operation):
  1. Path must be absolute. Relative paths are rejected so we never
     resolve against the daemon's cwd by accident.
  2. Any segment equal to `..` is rejected pre-resolve — defense in
     depth even though step 3 would catch it.
  3. Pathlib resolve (without strict, so missing files for write still
     work) → check the resolved path is_relative_to one of the
     allowlist prefixes. Symlinks that escape the allowlist are
     rejected because resolve() follows them.
  4. Read size cap — files larger than `max_read_bytes` truncate, with
     `truncated: true` in the result so the agent knows.
  5. Write size cap — payload content longer than `max_write_bytes` is
     rejected; the agent shouldn't be dumping 50MB blobs to disk in
     one tool call.

Allowlist source: constructor default (operator-wired at handler
factory time) PLUS per-persona `ctx.extra["files.allowed_paths"]`.
Same pattern as the web handler's hostname allowlist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import structlog

from limenal.protocol import Context, Handler, ToolResult, ToolSpec

log = structlog.get_logger(__name__)


DEFAULT_MAX_READ_BYTES = 1_000_000   # 1 MB
DEFAULT_MAX_WRITE_BYTES = 500_000    # 500 KB
DEFAULT_MAX_LIST_ENTRIES = 500


CARD = {
    "handler": "files",
    "required_scope": "files:access",
    "description": "Scoped file I/O against operator-allowlisted paths",
    "tools": [
        {"name": "read", "description": "Read a file's text content (UTF-8)."},
        {"name": "write", "description": "Write text content to a file."},
        {"name": "list", "description": "List entries in a directory."},
        {"name": "exists", "description": "Test whether a path exists."},
    ],
    "activation": "always",
    "relevance_signals": [
        "reading a project source file to answer a question about it",
        "writing notes or a draft to the operator's scratch directory",
        "exploring a directory's contents before making a recommendation",
    ],
    "credential_keys": [],
    "labels": {"tier": "builtin"},
}


@dataclass
class FilesConfig:
    """Operator config. allowed_paths is normalized to resolved absolute
    Paths once at construction so each request just does a startswith
    check instead of re-resolving on every call."""

    allowed_paths: list[Path] = field(default_factory=list)
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES
    max_write_bytes: int = DEFAULT_MAX_WRITE_BYTES
    max_list_entries: int = DEFAULT_MAX_LIST_ENTRIES

    def __post_init__(self) -> None:
        self.allowed_paths = [
            Path(p).expanduser().resolve()
            for p in self.allowed_paths
        ]


@dataclass
class FilesHandler:
    """Stateless. Per-persona allowlist override flows through
    ctx.extra["files.allowed_paths"] (a list[str]); falls back to
    default_config.allowed_paths."""

    default_config: FilesConfig = field(default_factory=FilesConfig)

    def tools(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="read",
                description=(
                    "Read a file's text content (UTF-8). Path must be "
                    "absolute and under the operator-configured allowlist."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "max_bytes": {
                            "type": "integer",
                            "description": "Caller-side cap; capped further by handler config.",
                        },
                    },
                    "required": ["path"],
                },
            ),
            ToolSpec(
                name="write",
                description="Write text content to a file (UTF-8). Creates parent dirs.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                        "create_parents": {
                            "type": "boolean",
                            "description": "Default true — mkdir -p the parent.",
                        },
                    },
                    "required": ["path", "content"],
                },
            ),
            ToolSpec(
                name="list",
                description="List entries in a directory.",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            ),
            ToolSpec(
                name="exists",
                description="Test whether a path exists (file or directory).",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
            ),
        ]

    def capability_card(self) -> dict[str, Any]:
        return CARD

    async def dispatch(
        self, name: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        raw_path = payload.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            return ToolResult.failure("'path' must be a non-empty string")

        cfg = self._resolve_config(ctx)
        resolved, err = self._safe_resolve(raw_path, cfg)
        if err is not None:
            return ToolResult.failure(err)

        if name == "read":
            return await self._read(resolved, payload, cfg)
        if name == "write":
            return await self._write(resolved, payload, cfg)
        if name == "list":
            return await self._list(resolved, cfg)
        if name == "exists":
            exists = await anyio.to_thread.run_sync(resolved.exists)
            return ToolResult.json({"path": str(resolved), "exists": exists})
        return ToolResult.failure(f"unknown tool {name!r}")

    # ---- defenses + resolution ---------------------------------------------

    def _resolve_config(self, ctx: Context) -> FilesConfig:
        per_persona = ctx.extra.get("files.allowed_paths")
        if not per_persona or not isinstance(per_persona, list):
            return self.default_config

        # Resolve JWT-supplied paths, skipping malformed entries.
        jwt_paths: list[Path] = []
        for raw in per_persona:
            if isinstance(raw, str) and raw:
                try:
                    jwt_paths.append(Path(raw).expanduser().resolve())
                except Exception:  # noqa: BLE001
                    pass

        if not jwt_paths:
            return self.default_config

        server_ceiling = self.default_config.allowed_paths  # already resolved

        if not server_ceiling:
            # No server-side ceiling: JWT paths are the allowlist.
            effective = jwt_paths
        else:
            # JWT can narrow, never widen.
            # A JWT path narrower than a server path is kept as-is.
            # A JWT path broader than a server path is clamped to the server path.
            # A JWT path with no overlap with any server path is dropped.
            effective_set: set[Path] = set()
            for sp in server_ceiling:
                for jp in jwt_paths:
                    if _is_under(sp, jp):
                        # JWT is broader: clamp to the server path.
                        effective_set.add(sp)
                    elif _is_under(jp, sp):
                        # JWT is narrower: keep the JWT path.
                        effective_set.add(jp)
            effective = list(effective_set)

        return FilesConfig(
            allowed_paths=effective,
            max_read_bytes=self.default_config.max_read_bytes,
            max_write_bytes=self.default_config.max_write_bytes,
            max_list_entries=self.default_config.max_list_entries,
        )

    def _safe_resolve(
        self, raw_path: str, cfg: FilesConfig
    ) -> tuple[Path | None, str | None]:
        """Apply the layered defenses; return (resolved_path, None) if OK
        or (None, error_message) if refused."""
        if not cfg.allowed_paths:
            return None, "no allowlist configured for this persona — refusing"

        candidate = Path(raw_path)
        if not candidate.is_absolute():
            return None, (
                f"path {raw_path!r} must be absolute (relative paths refused "
                "to avoid daemon-cwd ambiguity)"
            )

        # Defense in depth: reject .. segments before resolve(). resolve()
        # would catch escapes anyway, but we never want to silently follow
        # them.
        if any(part == ".." for part in candidate.parts):
            return None, f"path {raw_path!r} contains '..'"

        try:
            resolved = candidate.expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            return None, f"path resolution failed: {exc}"

        # Symlinks that escape get caught here because resolve() follows
        # them.
        for allowed in cfg.allowed_paths:
            if _is_under(resolved, allowed):
                return resolved, None
        return None, (
            f"path {resolved} not under any allowlisted prefix "
            f"({[str(p) for p in cfg.allowed_paths]})"
        )

    # ---- tools ------------------------------------------------------------

    async def _read(
        self, path: Path, payload: dict[str, Any], cfg: FilesConfig
    ) -> ToolResult:
        try:
            if not await anyio.to_thread.run_sync(path.exists):
                return ToolResult.failure(f"no such file: {path}")
            if not await anyio.to_thread.run_sync(path.is_file):
                return ToolResult.failure(f"not a file: {path}")
            cap = min(
                int(payload.get("max_bytes") or cfg.max_read_bytes),
                cfg.max_read_bytes,
            )
            data = await anyio.to_thread.run_sync(path.read_bytes)
        except OSError as exc:
            return ToolResult.failure(f"read failed: {exc}")
        truncated = False
        if len(data) > cap:
            data = data[:cap]
            truncated = True
        text = data.decode("utf-8", errors="replace")
        return ToolResult.json(
            {
                "path": str(path),
                "bytes": len(data),
                "truncated": truncated,
                "text": text,
            }
        )

    async def _write(
        self, path: Path, payload: dict[str, Any], cfg: FilesConfig
    ) -> ToolResult:
        content = payload.get("content")
        if not isinstance(content, str):
            return ToolResult.failure("'content' must be a string")
        encoded = content.encode("utf-8")
        if len(encoded) > cfg.max_write_bytes:
            return ToolResult.failure(
                f"content is {len(encoded)} bytes; exceeds "
                f"max_write_bytes={cfg.max_write_bytes}"
            )
        create_parents = bool(payload.get("create_parents", True))
        try:
            if create_parents:
                await anyio.to_thread.run_sync(
                    lambda: path.parent.mkdir(parents=True, exist_ok=True)
                )
            await anyio.to_thread.run_sync(lambda: path.write_bytes(encoded))
        except OSError as exc:
            return ToolResult.failure(f"write failed: {exc}")
        return ToolResult.json({"path": str(path), "bytes_written": len(encoded)})

    async def _list(self, path: Path, cfg: FilesConfig) -> ToolResult:
        try:
            if not await anyio.to_thread.run_sync(path.exists):
                return ToolResult.failure(f"no such directory: {path}")
            if not await anyio.to_thread.run_sync(path.is_dir):
                return ToolResult.failure(f"not a directory: {path}")

            max_entries = cfg.max_list_entries

            def _scan() -> list[dict[str, Any]]:
                entries: list[dict[str, Any]] = []
                for child in sorted(path.iterdir()):
                    if len(entries) > max_entries:
                        break
                    try:
                        stat = child.stat()
                        entries.append(
                            {
                                "name": child.name,
                                "type": "dir" if child.is_dir() else "file",
                                "size": stat.st_size if child.is_file() else None,
                            }
                        )
                    except OSError:
                        continue
                return entries

            entries = await anyio.to_thread.run_sync(_scan)
        except OSError as exc:
            return ToolResult.failure(f"list failed: {exc}")
        truncated = len(entries) > cfg.max_list_entries
        if truncated:
            entries = entries[: cfg.max_list_entries]
        return ToolResult.json(
            {
                "path": str(path),
                "entries": entries,
                "truncated": truncated,
            }
        )


def _is_under(candidate: Path, prefix: Path) -> bool:
    """True iff `candidate` is `prefix` itself or a descendant.

    `Path.is_relative_to` exists on 3.9+ but its semantics get fuzzy with
    symlinks already resolved on both sides — we keep this as an
    explicit string-prefix check on the resolved forms to avoid
    cross-platform surprises.
    """
    try:
        candidate.relative_to(prefix)
        return True
    except ValueError:
        return False


_SINGLETON: FilesHandler | None = None


def get_handler() -> Handler:
    """Entry-point factory.

    By default the handler ships with NO allowed paths — any read/write
    is refused until the operator wires `default_config.allowed_paths`
    (or a per-persona allowlist arrives in ctx.extra). This is the
    safe default: a freshly-installed limenal with `files` registered
    cannot read or write anything until the operator opts in.
    """
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = FilesHandler()
    return _SINGLETON
