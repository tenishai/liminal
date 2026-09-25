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
  6. Protected instruction files (#108) — a write to CLAUDE.md, AGENTS.md
     and the like, or anywhere under a `.claude/` directory, is refused
     unless the server-side policy grant holds `files:protected_writes`.
     See `_protected_match`.

Allowlist source: constructor default (operator-wired at handler
factory time, or from LIMINAL_FILES_ALLOWED_PATHS — see `get_handler`)
PLUS per-persona `ctx.extra["files.allowed_paths"]`. Same pattern as the
web handler's hostname allowlist.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import structlog

from liminal.protocol import Context, Handler, ToolResult, ToolSpec

log = structlog.get_logger(__name__)


DEFAULT_MAX_READ_BYTES = 1_000_000   # 1 MB
DEFAULT_MAX_WRITE_BYTES = 500_000    # 500 KB
DEFAULT_MAX_LIST_ENTRIES = 500


# ---- protected instruction files (#108) -------------------------------------
#
# Agent tools load these as INSTRUCTIONS in every later session run in that
# directory: Claude Code reads CLAUDE.md, and AGENTS.md when no CLAUDE.md is
# present. A persona that reads untrusted content and is steered into one
# files_write would turn a one-off injection into a persistent one. The path
# allowlist does not help, because the repo is meant to be writable.
#
# Matched case-insensitively, in any directory, against the requested path AND
# the resolved one, so neither case, `./`, a symlinked file nor a symlinked
# parent reaches a protected file under a different name. Ported in shape from
# hermes-agent's write guards (themselves from Roo-Code's RooProtectedController).
PROTECTED_BASENAMES: frozenset[str] = frozenset(
    {"claude.md", "claude.local.md", "agents.md", ".cursorrules", "gemini.md"}
)
# Anything beneath these directories. `.claude/settings.json` can register
# hooks, which is code execution, not just instructions.
PROTECTED_DIRS: frozenset[str] = frozenset({".claude"})

# The one grant that lifts the gate. Checked against `ctx.granted_scopes`, which
# only the server-side policy grant fills, so a token cannot grant it to itself.
# Explicit membership, deliberately: `admin:*` does NOT imply it, because an
# admin grant is given for managing liminal, not for rewriting agent prompts.
PROTECTED_WRITE_SCOPE = "files:protected_writes"


CARD = {
    "handler": "files",
    # Open for now: files has a read/write split that the per-HANDLER scope
    # gate can't express (a single scope can't separate read from write).
    # Deferred to per-tool scope enforcement, same as memory.
    "required_scope": None,
    "description": "Scoped file I/O against operator-allowlisted paths",
    "tools": [
        {"name": "read", "description": "Read a file's text content (UTF-8).", "required_scope": "files:read"},
        {"name": "write", "description": "Write text content to a file.", "required_scope": "files:write"},
        {"name": "list", "description": "List entries in a directory.", "required_scope": "files:read"},
        {"name": "exists", "description": "Test whether a path exists.", "required_scope": "files:read"},
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
            refusal = await self._gate_protected_write(raw_path, resolved, ctx)
            if refusal is not None:
                return refusal
            return await self._write(resolved, payload, cfg)
        if name == "list":
            return await self._list(resolved, cfg)
        if name == "exists":
            exists = await anyio.to_thread.run_sync(resolved.exists)
            return ToolResult.json({"path": str(resolved), "exists": exists})
        return ToolResult.failure(f"unknown tool {name!r}")

    # ---- defenses + resolution ---------------------------------------------

    def _resolve_config(self, ctx: Context) -> FilesConfig:
        # CLAIM ABSENT vs CLAIM EMPTY ARE DIFFERENT ANSWERS, and conflating them
        # turned the operator ceiling into a grant (#68 review). Before the env
        # var existed, `default_config` was always empty, so every fallback below
        # meant REFUSE and the distinction did not matter. Now the default can be
        # non-empty, and falling back on an empty claim widens a persona that
        # explicitly said "no paths" to the whole ceiling.
        #
        #   no `files.allowed_paths` key   -> operator default (may be the ceiling)
        #   key present, but unusable      -> REFUSE, never the default
        if "files.allowed_paths" not in ctx.extra:
            return self.default_config

        per_persona = ctx.extra.get("files.allowed_paths")
        if not isinstance(per_persona, list) or not per_persona:
            # Present and empty, or present and not a list: a claim was made and
            # it grants nothing. Fail closed rather than inheriting the ceiling.
            return FilesConfig(allowed_paths=[])

        # Resolve JWT-supplied paths, skipping malformed entries.
        jwt_paths: list[Path] = []
        for raw in per_persona:
            if isinstance(raw, str) and raw:
                try:
                    jwt_paths.append(Path(raw).expanduser().resolve())
                except Exception:  # noqa: BLE001
                    pass

        if not jwt_paths:
            # Every entry was malformed. The claim still said "these paths", and
            # none of them parsed — that is not a request for the ceiling.
            return FilesConfig(allowed_paths=[])

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

    async def _gate_protected_write(
        self, raw_path: str, resolved: Path, ctx: Context
    ) -> ToolResult | None:
        """Refuse a write to a protected instruction file unless granted.

        Returns None to let the write proceed. Every decision on a protected
        path is audited: a denial, and a granted write before it happens.
        """
        match = _protected_target(raw_path, resolved)
        if match is None:
            return None

        allowed = PROTECTED_WRITE_SCOPE in ctx.granted_scopes
        detail = {
            "tool": "files.write",
            "path": str(resolved),
            "protected": match,
            "reason": "protected write granted" if allowed else "protected instruction file",
        }
        log.warning("files.protected_write", allowed=allowed, **detail)
        try:
            if ctx.audit is not None:
                await ctx.audit(allowed=allowed, detail=detail)
        except Exception as exc:  # noqa: BLE001
            log.error("files.protected_write_audit_failed", error=str(exc))
            if allowed:
                # A granted write the audit log cannot record does not happen.
                return ToolResult.failure(
                    f"protected instruction file {str(resolved)!r}: audit record "
                    "failed, refusing the write"
                )

        if allowed:
            return None
        return ToolResult.failure(
            f"protected instruction file ({match}); requires operator grant. "
            f"{str(resolved)!r} is loaded as instructions by agent tools, so "
            "writing it needs the server-side "
            f"{PROTECTED_WRITE_SCOPE!r} grant. Report this rather than writing "
            "the content somewhere else."
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


def _protected_target(raw_path: str, resolved: Path) -> str | None:
    """Check both the requested path (normalised, not resolved) and the
    resolved one. The first catches a protected name that is a symlink to an
    ordinary file; the second catches an ordinary name, or a parent directory,
    that is a symlink to a protected one."""
    requested = Path(os.path.normpath(Path(raw_path).expanduser()))
    return _protected_match(requested) or _protected_match(resolved)


def _protected_match(path: Path) -> str | None:
    """The protected name `path` hits, or None. Case-insensitive, any depth."""
    parts = [part.casefold() for part in path.parts]
    if parts and parts[-1] in PROTECTED_BASENAMES:
        return parts[-1]
    for part in parts[:-1]:
        if part in PROTECTED_DIRS:
            return f"{part}/"
    return None


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


ALLOWED_PATHS_ENV = "LIMINAL_FILES_ALLOWED_PATHS"


def _paths_from_env(raw: str | None) -> list[Path]:
    """Parse LIMINAL_FILES_ALLOWED_PATHS into a list of paths.

    os.pathsep-separated, like PATH itself — ':' on POSIX, ';' on Windows.
    Empty segments are dropped so a trailing separator is harmless; an unset or
    all-empty value yields [], which is the fail-closed default. Segments are
    stripped before use, and a RELATIVE segment is refused with a warning rather
    than resolved against the daemon's cwd.
    """
    if not raw:
        return []
    out: list[Path] = []
    for seg in raw.split(os.pathsep):
        seg = seg.strip()
        if not seg:
            continue
        candidate = Path(seg).expanduser()
        if not candidate.is_absolute():
            # A RELATIVE CEILING RESOLVES AGAINST THE DAEMON'S CWD, which is the
            # same ambiguity defence #1 refuses relative REQUEST paths for. A
            # ceiling is the worse place for it: `.` would grant wherever the
            # daemon happened to start.
            log.warning(
                "files.allowlist.relative_path_ignored",
                segment=seg,
                env=ALLOWED_PATHS_ENV,
            )
            continue
        out.append(candidate)
    return out


def get_handler() -> Handler:
    """Entry-point factory.

    THE DEFAULT IS STILL EMPTY, AND STILL FAIL-CLOSED: with no allowlist
    from anywhere, every read and write is refused. What changed is that
    there is now a supported way to opt in without a JWT.

    WHAT THE ENV VALUE IS DEPENDS ON THE CALLER, and both halves matter:

      * a caller WITHOUT a `files.allowed_paths` claim gets it as a GRANT —
        this is what makes auth-off mode usable, and it means that in a JWT
        deployment every token lacking the claim receives it too;
      * a caller WITH a claim gets it as a CEILING — the claim narrows it and
        can never widen it (`_resolve_config`);
      * a caller whose claim is present but EMPTY or malformed gets NOTHING.
        A persona that grants no paths must not inherit the operator's.

    Why an env var rather than a `liminal serve --allowed-paths` flag:
    handlers are constructed by entry point, not by the CLI, so the CLI has
    no handle on this singleton to inject into. The env var is the seam
    that already exists — `LIMINAL_AUTH_DISABLED` and `LIMINAL_MEMORY_DB`
    are read the same way.

    This closes the gap in #68: in the auth-off mode the README recommends
    for local use, claims carry no `cabal_tool_extras`, so `ctx.extra` is
    empty and there was NO supported way to supply an allowlist at all. A
    safe default with no way to opt in is indistinguishable from broken.
    """
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = FilesHandler(
            default_config=FilesConfig(
                allowed_paths=_paths_from_env(os.environ.get(ALLOWED_PATHS_ENV))
            )
        )
    return _SINGLETON
