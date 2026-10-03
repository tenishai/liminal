"""files — scoped file I/O with path-traversal defense.

Scoped file I/O against an allowlist of paths. A caller's
`files.allowed_paths` (from the token's tool_extras, or in sovereign mode
the trust registry's [tool_extras]) and the operator's
LIMINAL_FILES_ALLOWED_PATHS combine as `get_handler()` and
`_resolve_config()` document: without a key the caller gets the operator
value; with a key, the operator value (when set) is a ceiling the key can
only narrow, and when unset the key itself is the allowlist; a present but
empty or malformed key grants nothing. Reads and
writes outside the allowlist return a structured error. Path traversal (..) is rejected before the
allowlist check.

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
  6. Protected paths (#108, #110) — a write to CLAUDE.md, AGENTS.md and the
     like, .mcp.json, .claude.json, .git/hooks/*, .git/config, or anywhere
     under a `.claude/` or `.cursor/` directory, is refused
     unless the server-side policy grant holds `files:protected_writes`.
     So is a write to a hard-linked file (when the extra link exists at the
     check; a link made after the open-time re-check and before the write
     ends is not caught), and to anything matching the operator's
     LIMINAL_FILES_PROTECTED_PATTERNS. See `_protected_match`.

Allowlist source: constructor default (operator-wired at handler
factory time, or from LIMINAL_FILES_ALLOWED_PATHS — see `get_handler`)
PLUS per-persona `ctx.extra["files.allowed_paths"]`. Same pattern as the
web handler's hostname allowlist.
"""

from __future__ import annotations

import fnmatch
import os
import stat
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
# directory (Claude Code reads CLAUDE.md; AGENTS.md, GEMINI.md and .cursorrules
# are the equivalents for other tools). A persona that reads untrusted content and is steered into one
# files_write would turn a one-off injection into a persistent one. The path
# allowlist does not help, because the repo is meant to be writable.
#
# Matched case-insensitively, in any directory, against the requested path AND
# the resolved one, so neither case, `./`, a symlinked file nor a symlinked
# parent reaches a protected file under a different name. A hard link would,
# so a hard-linked target is refused when the extra link exists at the check;
# a link made after the open-time re-check and before the write ends is not
# caught (see `_is_hard_linked`, `_write_unless_hard_linked`). Files a
# CLAUDE.md pulls in through `@path` imports are NOT covered (#110): which
# files those are depends on the content of every CLAUDE.md a later session
# loads, including ones outside the allowlist and ones edited after this
# write, so a write-time check cannot be complete. Shape follows the prior art
# cited in #108 (hermes-agent's write guards, ported from Roo-Code).
PROTECTED_BASENAMES: frozenset[str] = frozenset(
    {
        "claude.md", "claude.local.md", "agents.md", ".cursorrules", "gemini.md",
        ".windsurfrules", ".clinerules", ".roorules",
        # Code execution (#110): these register MCP servers, i.e. commands an
        # agent starts on its next launch in the tree.
        ".mcp.json", ".claude.json", ".git",
    }
)
# Anything beneath these directories. `.claude/settings.json` can register
# hooks, which is code execution, not just instructions. `.cursor/` holds
# rules, mcp.json and hooks.json. `.git` is protected whole: git loads hooks
# and config from `.git/hooks`, `.git/config`, `.git/modules/*/{hooks,config}`,
# and `.git/worktrees/*/commondir` can redirect a worktree to another common
# dir. (`.git/config` sets core.hooksPath, core.fsmonitor and core.sshCommand,
# all of which run commands.) `.github/` and `.gitignore` are different names
# and stay writable. `.gemini/settings.json` registers MCP servers for Gemini
# CLI, so `.gemini/` is a code-execution path too. `.clinerules/` (Cline's
# directory form) and `.roo/` (Roo Code's `rules/` and `rules-<mode>/`) hold instructions.
PROTECTED_DIRS: frozenset[str] = frozenset(
    {".claude", ".cursor", ".git", ".gemini", ".clinerules", ".roo"}
)
# Exact parent/child pairs naming a single file.
PROTECTED_FILE_PAIRS: frozenset[tuple[str, str]] = frozenset(
    {
        (".github", "copilot-instructions.md"),
        # VS Code's workspace MCP servers (code execution).
        (".vscode", "mcp.json"),
    }
)
# Parent/child directory pairs: anything beneath `<parent>/<child>/`. Copilot's
# path-specific instructions, Cline's alternative rules dir, and Windsurf's
# rules dirs (`.devin/rules` is its current name for `.windsurf/rules`). The
# parents themselves hold other things and stay writable.
PROTECTED_DIR_PAIRS: frozenset[tuple[str, str]] = frozenset(
    {
        (".github", "instructions"),
        (".cline", "rules"),
        (".windsurf", "rules"),
        (".devin", "rules"),
    }
)
# Built-in fnmatch patterns, checked like the operator's (see
# `_pattern_match`): Roo Code's per-mode single-file rules.
BUILTIN_PROTECTED_PATTERNS: tuple[str, ...] = (".roorules-*",)
# Names above that are code-execution paths rather than instruction files; used
# only to word the refusal. `.git` as a basename is the pointer file of a linked
# worktree or submodule checkout (`gitdir: <path>`), which redirects git to
# another gitdir and so to its config and hooks.
_EXEC_NAMES: frozenset[str] = frozenset(
    {".mcp.json", ".claude.json", ".git/", ".git", ".gemini/", ".vscode/mcp.json"}
)

# Reported as the match for a hard-linked target (see `_is_hard_linked`).
HARD_LINK_MATCH = "hard link"

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
    # Operator fnmatch patterns ADDED to the built-in protected set (#110).
    # There is no way to remove a built-in: the gate checks the built-ins
    # first and these only after. Read from `default_config` alone, never from
    # a per-persona config, so a token cannot add or drop one.
    protected_patterns: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.allowed_paths = [
            Path(p).expanduser().resolve()
            for p in self.allowed_paths
        ]
        self.protected_patterns = _normalise_patterns(self.protected_patterns)


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
            refusal, approved = await self._gate_protected_write(raw_path, resolved, ctx)
            if refusal is not None:
                return refusal
            return await self._write(resolved, payload, cfg, allow_hard_linked=approved)
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
    ) -> tuple[ToolResult | None, bool]:
        """Refuse a write to a protected instruction file unless granted.

        Returns (refusal, approved). A None refusal lets the write proceed;
        `approved` is True when a protected path matched and the grant holds,
        which is what lets `_write` go through a hard link. Every decision on a
        protected path is logged. It is also audited, a denial and a granted
        write before it happens, when `ctx.audit` is set; routes.py sets it
        only in sovereign mode (a grant and a policy store). With `ctx.audit`
        None a granted write is still approved and only logged.
        """
        match = _protected_target(
            raw_path, resolved, self.default_config.protected_patterns
        )
        if match is None and await anyio.to_thread.run_sync(_is_hard_linked, resolved):
            match = HARD_LINK_MATCH
        if match is None:
            return None, False

        allowed = PROTECTED_WRITE_SCOPE in ctx.granted_scopes
        if match in _EXEC_NAMES:
            kind = "code-execution path"
        elif match == HARD_LINK_MATCH:
            kind = "hard-linked file"
        elif match.startswith(_OPERATOR_PREFIX):
            kind = "operator-protected path"
        else:
            kind = "instruction file"
        detail = {
            "tool": "files.write",
            "path": str(resolved),
            "protected": match,
            "reason": "protected write granted" if allowed else f"protected {kind}",
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
                    f"protected {kind} {str(resolved)!r}: audit record "
                    "failed, refusing the write"
                ), False

        if allowed:
            return None, True
        return ToolResult.failure(
            f"protected {kind} ({match}); requires operator grant. "
            f"{str(resolved)!r} is loaded or run by agent tools and git, so "
            "writing it needs the server-side "
            f"{PROTECTED_WRITE_SCOPE!r} grant. Report this rather than writing "
            "the content somewhere else."
        ), False

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
        self,
        path: Path,
        payload: dict[str, Any],
        cfg: FilesConfig,
        *,
        allow_hard_linked: bool = False,
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
            linked = await anyio.to_thread.run_sync(
                _write_unless_hard_linked, path, encoded, allow_hard_linked
            )
        except OSError as exc:
            return ToolResult.failure(f"write failed: {exc}")
        if linked:
            # The gate saw one link; the open file has more. A link was made
            # between the gate's stat and the fstat, so the gate's answer no
            # longer holds.
            log.warning("files.hard_link_appeared", path=str(path))
            return ToolResult.failure(
                f"write refused: {str(path)!r} became a hard-linked file "
                "during the write; requires operator grant"
            )
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


def _protected_target(
    raw_path: str, resolved: Path, extra_patterns: list[str] | None = None
) -> str | None:
    """Check both the requested path (normalised, not resolved) and the
    resolved one. The first catches a protected name that is a symlink to an
    ordinary file; the second catches an ordinary name, or a parent directory,
    that is a symlink to a protected one."""
    requested = Path(os.path.normpath(Path(raw_path).expanduser()))
    extra = extra_patterns or []
    return _protected_match(requested, extra) or _protected_match(resolved, extra)


def _protected_match(path: Path, extra_patterns: list[str] | None = None) -> str | None:
    """The protected name `path` hits, or None. Case-insensitive, any depth.

    Built-ins are checked first, so an operator pattern can only add to them.
    """
    parts = [part.casefold() for part in path.parts]
    if parts and parts[-1] in PROTECTED_BASENAMES:
        return parts[-1]
    if len(parts) >= 2 and (parts[-2], parts[-1]) in PROTECTED_FILE_PAIRS:
        return f"{parts[-2]}/{parts[-1]}"
    for part in parts[:-1]:
        if part in PROTECTED_DIRS:
            return f"{part}/"
    for pair in zip(parts[:-2], parts[1:-1], strict=True):
        if pair in PROTECTED_DIR_PAIRS:
            return f"{pair[0]}/{pair[1]}/"
    whole = path.as_posix().casefold()
    for pattern in BUILTIN_PROTECTED_PATTERNS:
        if _pattern_match(pattern, parts, whole):
            return pattern
    for pattern in extra_patterns or []:
        if _pattern_match(pattern, parts, whole):
            return f"{_OPERATOR_PREFIX}{pattern}"
    return None


# Prefix on an operator pattern's match, so the refusal says where it came from.
_OPERATOR_PREFIX = "operator pattern "


def _pattern_match(pattern: str, parts: list[str], whole: str) -> bool:
    """fnmatch `pattern` (already casefolded) against casefolded `parts`
    and the casefolded POSIX form of the whole path.

    A pattern with no `/` is a NAME: it matches any component, the file or a
    directory above it, so `.husky` protects everything under `.husky/` and
    `*.env` protects every `.env` file. A pattern with a `/` is a PATH,
    matched against the whole path; unless it starts with `/` or `*` it is
    anchored at any directory, so `.husky/*` matches `<anything>/.husky/...`.
    A PATH also protects everything beneath what it matches, the same as a
    NAME does, so `sub/.husky` (or `sub/.husky/`, the trailing `/` having been
    dropped by `_normalise_patterns`) covers `sub/.husky/pre-commit`.
    `*` crosses `/` (plain fnmatch), so one `*` covers any depth.
    """
    if "/" not in pattern:
        return any(fnmatch.fnmatchcase(part, pattern) for part in parts)
    if not pattern.startswith(("/", "*")):
        pattern = "*/" + pattern
    return fnmatch.fnmatchcase(whole, pattern) or fnmatch.fnmatchcase(
        whole, pattern.rstrip("/") + "/*"
    )


def _is_hard_linked(path: Path) -> bool:
    """True if `path` is an existing regular file with more than one link.

    THE RULE IS "ANY HARD LINK", NOT "A HARD LINK TO A PROTECTED FILE", because
    the second cannot be decided correctly here. A link's other names are not
    recorded on the inode; finding them means scanning every directory on the
    filesystem, and the protected file it shares may sit outside the allowlist
    (`~/.claude.json`, `~/.claude/CLAUDE.md`) where this handler does not look.
    Name matching sees only the name the caller used. So any regular file with
    st_nlink > 1 is treated as protected and needs the same grant. Hard links
    are rare in a tree an agent writes to; the common case is a package
    store's hard-linked install (pnpm, uv), where writing through the link
    would also change the shared store, so refusing is right there too.
    """
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_nlink > 1


def _write_unless_hard_linked(path: Path, data: bytes, allow_hard_linked: bool) -> bool:
    """Write `data` to `path`; return True, writing nothing, if the open file
    turns out hard-linked and that was not approved.

    Opens WITHOUT truncating and checks the link count on the open descriptor,
    so the inode checked is the inode written. This NARROWS the window left by
    the gate's `_is_hard_linked`; it does not close it. A link made after the
    fstat below and before the write loop ends is not seen, and the content
    reaches the linked file. Closing that would need the check and the write
    to be one atomic step, which POSIX does not offer for an in-place write.
    """
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o666)
    try:
        st = os.fstat(fd)
        if stat.S_ISREG(st.st_mode) and st.st_nlink > 1 and not allow_hard_linked:
            return True
        os.ftruncate(fd, 0)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    finally:
        os.close(fd)
    return False


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


PROTECTED_PATTERNS_ENV = "LIMINAL_FILES_PROTECTED_PATTERNS"


def _normalise_patterns(raw: list[str]) -> list[str]:
    """Strip, casefold, drop empties, and drop a trailing `/` (except on a lone `/`). That is safe
    because every pattern already protects what lies beneath its match (see
    `_pattern_match`). Matching is case-insensitive, like the built-ins."""
    out: list[str] = []
    for pattern in raw:
        if not isinstance(pattern, str):
            continue
        pattern = pattern.strip().replace("\\", "/").casefold()
        if len(pattern) > 1:
            pattern = pattern.rstrip("/")
        if pattern:
            out.append(pattern)
    return out


def _patterns_from_env(raw: str | None) -> list[str]:
    """Parse LIMINAL_FILES_PROTECTED_PATTERNS into fnmatch patterns.

    os.pathsep-separated, like LIMINAL_FILES_ALLOWED_PATHS. These are added to
    the built-in protected set and cannot remove from it; unset adds nothing.
    """
    if not raw:
        return []
    return _normalise_patterns(raw.split(os.pathsep))


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
        can never widen it (`_resolve_config`); when the env value is unset or
        empty there is no ceiling, and the claim's paths are the allowlist;
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
                allowed_paths=_paths_from_env(os.environ.get(ALLOWED_PATHS_ENV)),
                protected_patterns=_patterns_from_env(
                    os.environ.get(PROTECTED_PATTERNS_ENV)
                ),
            )
        )
    return _SINGLETON
