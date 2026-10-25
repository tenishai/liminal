"""memory — techne-backed knowledge recall + commit.

Local techne queries against a SQLite DB. Which file a call uses (a
per-persona `memory.db_path` override, the LIMINAL_MEMORY_DB default, or a
refusal) is decided in `_resolve_db_path`; `MemoryConfig` documents the
override and refusal rules, and `get_handler()` seeds the default from
LIMINAL_MEMORY_DB.
No credentials required.

Architectural note: in Cabal, the Archivist persona already has direct
techne access via its `memory_store`. This handler is for the *other*
personas — Architect, Librarian, Rook subordinates — that want to read
from and contribute to the same knowledge corpus through liminal's
unified tool interface. The DB path is configurable per-persona via
`ctx.extra["memory.db_path"]`, so personas can share or isolate as the
operator wishes.

techne is a lazy import — the handler is usable even when techne isn't
installed (every dispatch errors with a structured "techne not
available" message). This keeps liminal's core dep graph small and
lets operators deploy with or without the memory handler.

Tools:
  memory.recall(query, limit?)
    FTS5-stemmed search over the knowledge table. Query string is
    sanitized: punctuation stripped, stop-words dropped, tokens
    OR-joined (same pattern as Cabal's TechneMemoryStore.recall).
  memory.commit(content, type?, tags?, confidence?)
    Append a knowledge entry. `type` must be one of techne's VALID_TYPES
    (fact, decision, pattern, evaluation, procedure); other values
    error with the list of acceptable choices. `confidence` is
    low/medium/high.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import structlog

from liminal.protocol import Context, Handler, ToolResult, ToolSpec

log = structlog.get_logger(__name__)


try:
    from techne import VALID_TYPES
except ImportError:
    VALID_TYPES = ("fact", "decision", "pattern", "evaluation", "procedure")
VALID_CONFIDENCE = ("low", "medium", "high")


# FTS5 special characters we strip + stopwords we drop before OR-joining
# the query tokens (matches the Cabal TechneMemoryStore._sanitize_query
# pattern so recall semantics are consistent across the platform).
_FTS5_SPECIALS = re.compile(r"""[^\w\s\-]""")
_STOPWORDS = frozenset({
    "a", "an", "the", "and", "or", "of", "in", "to", "for", "on", "at",
    "do", "does", "did", "is", "are", "was", "were", "be", "been",
    "i", "you", "he", "she", "it", "we", "they", "me", "my", "your",
    "what", "who", "when", "where", "why", "how", "which",
    "near", "not",  # FTS5 keywords
})


CARD = {
    "handler": "memory",
    # Open for now: memory has a read/write split (recall vs commit) that the
    # per-HANDLER scope gate can't express — the federation vocabulary
    # (mem:query vs mem:append) is per-TOOL. Enforcing a single handler-level
    # scope here would either lock out documented grants or silently collapse
    # the query/append distinction. Deferred to per-tool scope enforcement.
    "required_scope": None,
    "description": "techne-backed knowledge recall + commit (per-persona DB)",
    "tools": [
        {
            "name": "recall",
            "description": "Search the knowledge corpus for entries relevant to a query.",
            "required_scope": "mem:query",  # read
        },
        {
            "name": "commit",
            "description": "Persist a new knowledge entry (fact / decision / pattern / evaluation / procedure).",
            "required_scope": "mem:append",  # write
        },
    ],
    "activation": "always",
    "credential_keys": [],
    "labels": {"tier": "builtin", "backend": "techne"},
}


@dataclass
class MemoryConfig:
    """Operator config. db_path is the fallback when no per-persona
    override arrives via ctx.extra.

    allowed_db_dirs constrains which directories a JWT-supplied
    memory.db_path override may point to. If empty and db_path is set,
    the allowed dir is derived from db_path.parent. If both are unset,
    JWT overrides are rejected (fail closed).
    """

    db_path: Path | None = None
    allowed_db_dirs: list[Path] = field(default_factory=list)
    use_vectors: bool = False
    default_recall_limit: int = 5


@dataclass
class MemoryHandler:
    default_config: MemoryConfig = field(default_factory=MemoryConfig)

    def status(self) -> str | None:
        """liminal#191: with no default db every call without a per-persona
        memory.db_path override is refused, so say so instead of ready."""
        if self.default_config.db_path is not None:
            return None
        return (
            "unconfigured: LIMINAL_MEMORY_DB is unset (only a token's memory.db_path "
            "override can name a store)"
        )

    def tools(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="recall",
                description="Search the knowledge corpus.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                    },
                    "required": ["query"],
                },
            ),
            ToolSpec(
                name="commit",
                description="Persist a new knowledge entry.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "content": {"type": "string"},
                        "type": {
                            "type": "string",
                            "enum": list(VALID_TYPES),
                            "default": "fact",
                        },
                        "tags": {
                            "type": "string",
                            "description": "Free-form comma-separated tags.",
                        },
                        "confidence": {
                            "type": "string",
                            "enum": list(VALID_CONFIDENCE),
                            "default": "medium",
                        },
                    },
                    "required": ["content"],
                },
            ),
        ]

    def capability_card(self) -> dict[str, Any]:
        return CARD

    async def dispatch(
        self, name: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        db_path = self._resolve_db_path(ctx)
        if db_path is None:
            return ToolResult.failure(
                "no memory DB configured for this persona (set default_config.db_path "
                "or pass ctx.extra['memory.db_path'])"
            )

        try:
            import techne  # type: ignore[import-not-found]
        except ImportError as exc:
            return ToolResult.failure(
                f"techne not installed; memory handler unavailable ({exc})"
            )

        if name == "recall":
            return await self._recall(techne, db_path, payload)
        if name == "commit":
            return await self._commit(techne, db_path, payload)
        return ToolResult.failure(f"unknown tool {name!r}")

    # ---- per-request config ----------------------------------------------

    def _resolve_db_path(self, ctx: Context) -> Path | None:
        override = ctx.extra.get("memory.db_path")
        if not override:
            return self.default_config.db_path

        # Apply the files-handler treatment: reject .., resolve, check ceiling.
        candidate = Path(override)
        if any(part == ".." for part in candidate.parts):
            log.warning("memory.db_path_rejected", reason="contains ..", path=override)
            return None

        try:
            resolved = candidate.expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            log.warning("memory.db_path_rejected", reason="resolve failed", error=str(exc))
            return None

        # Build the set of allowed base directories.
        allowed_dirs: list[Path] = list(self.default_config.allowed_db_dirs)
        if not allowed_dirs and self.default_config.db_path is not None:
            allowed_dirs = [self.default_config.db_path.parent.resolve()]

        if not allowed_dirs:
            # No operator-configured ceiling at all — fail closed.
            log.warning("memory.db_path_rejected", reason="no allowed_db_dirs configured")
            return None

        for base in allowed_dirs:
            try:
                resolved.relative_to(base)
                return resolved
            except ValueError:
                pass

        log.warning(
            "memory.db_path_rejected",
            reason="outside allowed dirs",
            path=str(resolved),
            allowed=[str(d) for d in allowed_dirs],
        )
        return None

    # ---- tools ----------------------------------------------------------

    async def _recall(self, techne: Any, db_path: Path, payload: dict[str, Any]) -> ToolResult:
        query = payload.get("query")
        if not isinstance(query, str) or not query.strip():
            return ToolResult.failure("'query' must be a non-empty string")

        sanitized = _sanitize_query(query)
        if not sanitized:
            return ToolResult.json({"query": query, "hits": []})

        limit = payload.get("limit")
        if limit is None:
            limit = self.default_config.default_recall_limit
        elif isinstance(limit, bool) or not isinstance(limit, int):
            return ToolResult.failure(
                f"'limit' must be an integer, got {type(limit).__name__}"
            )
        limit = max(1, min(limit, 50))
        use_vectors = self.default_config.use_vectors

        try:
            results = await anyio.to_thread.run_sync(
                lambda: techne.search.search(
                    db_path,
                    sanitized,
                    table="knowledge",
                    limit=limit,
                    use_vectors=use_vectors,
                )
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult.failure(f"recall failed: {exc}")

        hits = [
            {
                "content": r.get("content", ""),
                "type": r.get("knowledge_type") or r.get("type"),
                "confidence": r.get("confidence"),
                "tags": r.get("tags") or "",
                "score": r.get("rank"),
            }
            for r in results
        ]
        return ToolResult.json({"query": query, "hits": hits})

    async def _commit(self, techne: Any, db_path: Path, payload: dict[str, Any]) -> ToolResult:
        content = payload.get("content")
        if not isinstance(content, str) or not content.strip():
            return ToolResult.failure("'content' must be a non-empty string")

        ktype = payload.get("type", "fact")
        if ktype not in VALID_TYPES:
            return ToolResult.failure(
                f"'type' must be one of {list(VALID_TYPES)}; got {ktype!r}"
            )
        confidence = payload.get("confidence", "medium")
        if confidence not in VALID_CONFIDENCE:
            return ToolResult.failure(
                f"'confidence' must be one of {list(VALID_CONFIDENCE)}; got {confidence!r}"
            )
        tags = payload.get("tags", "")
        if not isinstance(tags, str):
            return ToolResult.failure("'tags' must be a string")

        if not await anyio.to_thread.run_sync(db_path.exists):
            try:
                await anyio.to_thread.run_sync(
                    lambda: db_path.parent.mkdir(parents=True, exist_ok=True)
                )
                await anyio.to_thread.run_sync(lambda: techne.init_db(db_path))
            except Exception as exc:  # noqa: BLE001
                return ToolResult.failure(f"could not initialize techne DB: {exc}")

        try:
            await anyio.to_thread.run_sync(
                lambda: techne.knowledge.store(
                    db_path,
                    content=content,
                    type=ktype,
                    tags=tags,
                    confidence=confidence,
                    source="liminal",
                )
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult.failure(f"commit failed: {exc}")

        return ToolResult.json(
            {"committed": True, "type": ktype, "confidence": confidence}
        )


def _sanitize_query(query: str) -> str:
    """Strip FTS5 specials, drop stopwords, OR-join the rest.

    Mirrors Cabal's TechneMemoryStore._sanitize_query so personas using
    the liminal memory handler and Archivist's direct techne path see
    the same recall semantics on identical corpora.
    """
    cleaned = _FTS5_SPECIALS.sub(" ", query).lower()
    tokens = [
        t for t in cleaned.split()
        if len(t) > 1 and t not in _STOPWORDS
    ]
    return " OR ".join(tokens)


_SINGLETON: MemoryHandler | None = None


def get_handler() -> Handler:
    """Entry-point factory.

    If ``LIMINAL_MEMORY_DB`` is set, it seeds ``default_config.db_path`` so a
    served handler (``liminal serve``) has a fixed fallback corpus without a
    per-call override. A per-persona ``ctx.extra['memory.db_path']`` still
    takes precedence (within the allowed-dir ceiling). With neither set, the
    handler has no DB path and refuses every dispatch with a structured error.

    Note: the env var is read once, when the process-wide singleton is first
    built. Use an absolute or ``~``-rooted path — unlike a ``ctx.extra``
    override (which is ``resolve()``'d), the env-seeded path is only
    ``expanduser()``'d, so a relative value is interpreted against the
    process CWD lazily at dispatch time rather than pinned at startup.
    """
    global _SINGLETON
    if _SINGLETON is None:
        db_env = os.environ.get("LIMINAL_MEMORY_DB")
        config = (
            MemoryConfig(db_path=Path(db_env).expanduser()) if db_env else MemoryConfig()
        )
        _SINGLETON = MemoryHandler(default_config=config)
    return _SINGLETON
