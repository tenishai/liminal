"""Server-side authorization policy for a sovereign liminal (federation Part 2).

A *sovereign* liminal (a graduated singleton persona serving several
independently-owned cabals) cannot derive authorization from claims the caller's
own cabal minted — a foreign cabal would just mint itself generous
`scope`/`tool_extras`. So authorization moves here: a policy table keyed on the
**verified** `(issuer, persona)` that this service owns.

Resolution precedence: exact `(issuer, persona)` → issuer-wide `(issuer, "*")` →
`None` (deny). Fail-closed. Parent rows never resolve on this data-plane path
(liminal#73): guardianship is admin standing, not tool access, and a topology
where the parent issuer also signs agent tokens (a cabal serving its own
graduated persona) must not hand `admin:*` to every ungranted agent through
the wildcard fallback. The admin surface resolves parents through
`resolve_parent` instead.

The **parent** — the cabal that graduated this persona — is seeded as an immutable
`is_parent` row with `admin:*`. No `grant`/`revoke` can touch it: "graduation does
not orphan." `admin:*` implies every scope. Parent rows are seeded per persona:
`parent_personas=("*",)` (the default) keeps the historical any-persona
guardianship; naming personas narrows admin standing to exactly those.

This is liminal's first local persistent store: a small SQLite DB. All access is
serialized through an asyncio lock and run off the event loop via `to_thread`, so
the single connection is never touched concurrently.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, TypeVar

_T = TypeVar("_T")

ADMIN_SCOPE = "admin:*"


@dataclass(frozen=True, slots=True)
class ScopeGrant:
    """What a caller may do. `allowed_handlers=None` means every handler this
    service exposes; an empty set denies all (fail-closed)."""

    scopes: frozenset[str]
    allowed_handlers: frozenset[str] | None = None

    def has_scope(self, required: str) -> bool:
        return ADMIN_SCOPE in self.scopes or required in self.scopes


@dataclass(frozen=True, slots=True)
class GrantRow:
    issuer: str
    persona: str
    scopes: frozenset[str]
    allowed_handlers: frozenset[str] | None
    is_parent: bool


@dataclass(frozen=True, slots=True)
class AuditRow:
    ts: float
    action: str
    issuer: str | None
    persona: str | None
    agent: str | None
    detail: dict[str, Any]


class ParentNarrowingConflict(ValueError):
    """Raised when `admin_personas` asks to narrow a store that already holds a
    WILDCARD parent row.

    Seeding is idempotent per (issuer, persona), so adding named personas to a
    store seeded under the historical wildcard ADDS rows without removing the
    wildcard — and `resolve_parent` falls back to that wildcard, so every
    persona the parent mints still holds admin. The narrowing is a no-op.

    The sting is the interaction: setting `admin_personas` also SILENCES the
    boot warning, so the operator does exactly what the warning asks, gets no
    warning back, and remains fully exposed. The control and its compensating
    signal fail together (Prudence, liminal#83 round 1).

    Refusing is deliberate rather than migrating silently: the docstring on
    _seed_parent already states that narrowing an existing wildcard deployment
    means a new policy DB, a deliberate operator act. This makes that stated
    intent ENFORCED instead of merely documented.
    """



class ParentImmutable(RuntimeError):
    """Attempt to modify or remove the parent's guardian grant."""


class PolicyStore(Protocol):
    async def resolve(self, issuer: str, persona: str) -> ScopeGrant | None: ...
    async def resolve_parent(self, issuer: str, persona: str) -> ScopeGrant | None: ...
    async def grant(
        self,
        issuer: str,
        persona: str,
        *,
        scopes: set[str],
        allowed_handlers: set[str] | None,
    ) -> None: ...
    async def revoke(self, issuer: str, persona: str) -> None: ...
    async def list_grants(self) -> list[GrantRow]: ...
    async def record_access(
        self, *, issuer: str, persona: str, agent: str | None, allowed: bool, detail: dict[str, Any]
    ) -> None: ...
    async def audit(
        self, *, since: float | None = None, limit: int = 100
    ) -> list[AuditRow]: ...
    def parents(self) -> frozenset[str]: ...


_SCHEMA = """
CREATE TABLE IF NOT EXISTS policy_grants (
    issuer            TEXT NOT NULL,
    persona           TEXT NOT NULL,
    scopes            TEXT NOT NULL,
    allowed_handlers  TEXT,
    is_parent         INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (issuer, persona)
);
CREATE TABLE IF NOT EXISTS policy_audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    action   TEXT NOT NULL,
    issuer   TEXT,
    persona  TEXT,
    agent    TEXT,
    detail   TEXT
);
"""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _dump_handlers(handlers: set[str] | None) -> str | None:
    return json.dumps(sorted(handlers)) if handlers is not None else None


def _load_handlers(raw: str | None) -> frozenset[str] | None:
    return frozenset(json.loads(raw)) if raw is not None else None


def _row_to_grant(row: sqlite3.Row) -> ScopeGrant:
    return ScopeGrant(
        scopes=frozenset(json.loads(row["scopes"])),
        allowed_handlers=_load_handlers(row["allowed_handlers"]),
    )


class SqlitePolicyStore:
    """SQLite-backed `PolicyStore`. Seeds the immutable parent row on init."""

    def __init__(
        self,
        path: str,
        *,
        parent_issuer: str | None = None,
        parent_scopes: tuple[str, ...] = (ADMIN_SCOPE,),
        parent_personas: tuple[str, ...] = ("*",),
        audit_max_rows: int | None = 50_000,
        audit_prune_interval: int = 500,
    ) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = asyncio.Lock()
        # Bound the audit table so an authenticated-but-ungranted (or
        # repeatedly-denied) partner cabal can't fill the DB — a plausible
        # availability vector across a federation. Trimmed to the most recent
        # `audit_max_rows` every `audit_prune_interval` writes. None = unbounded.
        self._audit_max_rows = audit_max_rows
        self._audit_prune_interval = max(1, audit_prune_interval)
        self._audit_writes = 0
        if parent_issuer is not None:
            self._seed_parent(parent_issuer, set(parent_scopes), parent_personas)
        # Parent set is immutable after seeding; cache it for the sync parents().
        self._parents = frozenset(
            r["issuer"]
            for r in self._conn.execute(
                "SELECT issuer FROM policy_grants WHERE is_parent = 1"
            ).fetchall()
        )

    def _seed_parent(
        self, issuer: str, scopes: set[str], personas: tuple[str, ...]
    ) -> None:
        """Seed one immutable parent row per persona. A store seeded before
        this issuer/persona pair existed keeps its rows (idempotent per pair);
        narrowing an existing wildcard deployment means a new policy DB, a
        deliberate operator act rather than a silent migration."""
        now = _now_iso()
        wanted = personas or ("*",)
        # DETECT ANY NO-OP NARROWING, not just the wildcard one.
        #
        # The first version of this check fired only when the EXISTING row was
        # the wildcard, and that was closed in one direction only. The hazard is
        # not a property of the wildcard: it is a property of seeding being
        # idempotent per (issuer, persona) WHILE ROWS ARE IMMUTABLE, which is
        # equally true of named rows. So de-listing a named admin — the ordinary
        # act of rotating someone out — was a silent no-op: the dropped
        # persona's is_parent row survived, resolve_parent kept answering for
        # it, and the running server never re-consults the registry. Driven over
        # the real HTTP surface by the reviewer: a de-listed persona's token got
        # 200 on GET /admin/policy and successfully granted admin:* to a partner
        # cabal (Prudence, liminal#83 round 2).
        #
        # It was WORSE than the unfixed state in one respect, which is the part
        # worth remembering: refusing loudly for the wildcard case taught the
        # operator that liminal enforces narrowing, so silence in the named case
        # read as "the narrowing took".
        #
        # Comparing the whole set subsumes the wildcard case rather than
        # special-casing it. Widening still passes ({"a"} -> {"a","b"} drops
        # nothing); first boot passes on an empty existing set.
        existing = {
            r["persona"]
            for r in self._conn.execute(
                "SELECT persona FROM policy_grants "
                "WHERE issuer = ? AND is_parent = 1",
                (issuer,),
            )
        }
        dropped = existing - set(wanted)
        if dropped:
            raise ParentNarrowingConflict(
                f"policy DB already holds parent row(s) for issuer {issuer!r} "
                f"covering persona(s) {sorted(dropped)!r}, which "
                f"admin_personas={sorted(wanted)!r} drops. Those rows are "
                f"immutable by design and would keep admin standing on "
                f"/admin/* regardless of the registry. Point --policy-db at a "
                f"new database to adopt this set."
            )
        for persona in wanted:
            existing = self._conn.execute(
                "SELECT 1 FROM policy_grants "
                "WHERE issuer = ? AND persona = ? AND is_parent = 1",
                (issuer, persona),
            ).fetchone()
            if existing is not None:
                continue
            self._conn.execute(
                "INSERT INTO policy_grants"
                "(issuer, persona, scopes, allowed_handlers, is_parent, created_at, updated_at) "
                "VALUES (?, ?, ?, NULL, 1, ?, ?)",
                (issuer, persona, json.dumps(sorted(scopes | {ADMIN_SCOPE})), now, now),
            )
        self._conn.commit()

    def parents(self) -> frozenset[str]:
        return self._parents

    async def _run(self, fn: Callable[[], _T]) -> _T:
        async with self._lock:
            return await asyncio.to_thread(fn)

    async def resolve(self, issuer: str, persona: str) -> ScopeGrant | None:
        """Data-plane resolution. Parent rows are excluded on BOTH legs
        (liminal#73): when the parent issuer also signs agent tokens, the
        wildcard fallback would otherwise hand `admin:*` to every ungranted
        agent -- and a caller whose verified identity is literally "*" must
        not hit the parent row on the exact leg either."""

        def _q() -> ScopeGrant | None:
            for who in (persona, "*"):
                row = self._conn.execute(
                    "SELECT scopes, allowed_handlers FROM policy_grants "
                    "WHERE issuer = ? AND persona = ? AND is_parent = 0",
                    (issuer, who),
                ).fetchone()
                if row is not None:
                    return _row_to_grant(row)
            return None

        return await self._run(_q)

    async def resolve_parent(self, issuer: str, persona: str) -> ScopeGrant | None:
        """Admin-plane resolution: ONLY parent rows, exact persona first,
        then the wildcard parent row when one was seeded. The admin surface
        is the sole caller (liminal#73)."""

        def _q() -> ScopeGrant | None:
            for who in (persona, "*"):
                row = self._conn.execute(
                    "SELECT scopes, allowed_handlers FROM policy_grants "
                    "WHERE issuer = ? AND persona = ? AND is_parent = 1",
                    (issuer, who),
                ).fetchone()
                if row is not None:
                    return _row_to_grant(row)
            return None

        return await self._run(_q)

    async def grant(
        self,
        issuer: str,
        persona: str,
        *,
        scopes: set[str],
        allowed_handlers: set[str] | None,
    ) -> None:
        def _op() -> None:
            existing = self._conn.execute(
                "SELECT is_parent FROM policy_grants WHERE issuer = ? AND persona = ?",
                (issuer, persona),
            ).fetchone()
            if existing is not None and existing["is_parent"]:
                raise ParentImmutable(
                    f"cannot modify parent grant ({issuer!r}, {persona!r})"
                )
            now = _now_iso()
            self._conn.execute(
                "INSERT INTO policy_grants"
                "(issuer, persona, scopes, allowed_handlers, is_parent, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 0, ?, ?) "
                "ON CONFLICT(issuer, persona) DO UPDATE SET "
                "scopes = excluded.scopes, allowed_handlers = excluded.allowed_handlers, "
                "updated_at = excluded.updated_at",
                (issuer, persona, json.dumps(sorted(scopes)), _dump_handlers(allowed_handlers), now, now),
            )
            self._audit(
                "grant", issuer, persona, None,
                {"scopes": sorted(scopes), "allowed_handlers": (sorted(allowed_handlers) if allowed_handlers is not None else None)},
            )
            self._conn.commit()

        await self._run(_op)

    async def revoke(self, issuer: str, persona: str) -> None:
        def _op() -> None:
            existing = self._conn.execute(
                "SELECT is_parent FROM policy_grants WHERE issuer = ? AND persona = ?",
                (issuer, persona),
            ).fetchone()
            if existing is None:
                return
            if existing["is_parent"]:
                raise ParentImmutable(
                    f"cannot revoke parent grant ({issuer!r}, {persona!r})"
                )
            self._conn.execute(
                "DELETE FROM policy_grants WHERE issuer = ? AND persona = ?",
                (issuer, persona),
            )
            self._audit("revoke", issuer, persona, None, {})
            self._conn.commit()

        await self._run(_op)

    async def list_grants(self) -> list[GrantRow]:
        def _q() -> list[GrantRow]:
            rows = self._conn.execute(
                "SELECT issuer, persona, scopes, allowed_handlers, is_parent "
                "FROM policy_grants ORDER BY issuer, persona"
            ).fetchall()
            return [
                GrantRow(
                    issuer=r["issuer"],
                    persona=r["persona"],
                    scopes=frozenset(json.loads(r["scopes"])),
                    allowed_handlers=_load_handlers(r["allowed_handlers"]),
                    is_parent=bool(r["is_parent"]),
                )
                for r in rows
            ]

        return await self._run(_q)

    async def record_access(
        self, *, issuer: str, persona: str, agent: str | None, allowed: bool, detail: dict[str, Any]
    ) -> None:
        def _op() -> None:
            self._audit(
                "access_allow" if allowed else "access_deny", issuer, persona, agent, detail
            )
            self._conn.commit()

        await self._run(_op)

    async def audit(
        self, *, since: float | None = None, limit: int = 100
    ) -> list[AuditRow]:
        def _q() -> list[AuditRow]:
            if since is not None:
                rows = self._conn.execute(
                    "SELECT ts, action, issuer, persona, agent, detail FROM policy_audit "
                    "WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
                    (since, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ts, action, issuer, persona, agent, detail FROM policy_audit "
                    "ORDER BY ts DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [
                AuditRow(
                    ts=r["ts"],
                    action=r["action"],
                    issuer=r["issuer"],
                    persona=r["persona"],
                    agent=r["agent"],
                    detail=json.loads(r["detail"]) if r["detail"] else {},
                )
                for r in rows
            ]

        return await self._run(_q)

    def _audit(
        self, action: str, issuer: str | None, persona: str | None, agent: str | None, detail: dict[str, Any]
    ) -> None:
        self._conn.execute(
            "INSERT INTO policy_audit(ts, action, issuer, persona, agent, detail) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), action, issuer, persona, agent, json.dumps(detail) if detail else None),
        )
        self._audit_writes += 1
        if (
            self._audit_max_rows is not None
            and self._audit_writes % self._audit_prune_interval == 0
        ):
            self._conn.execute(
                "DELETE FROM policy_audit WHERE id <= "
                "(SELECT MAX(id) FROM policy_audit) - ?",
                (self._audit_max_rows,),
            )

    def close(self) -> None:
        self._conn.close()
