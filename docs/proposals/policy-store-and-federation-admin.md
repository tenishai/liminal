# PolicyStore + `cbl federation` Admin Surface — spec

|  |  |
| --- | --- |
| **Status** | Implemented (`SqlitePolicyStore` in `src/liminal/server/policy.py`, admin router in `src/liminal/server/admin.py`) |
| **Authors** | Richard DiMartino + Raven (AI) |
| **Created** | 2026-07-02 |
| **Follows** | `docs/proposals/multi-issuer-trust-registry.md` (Part 2 referenced this) |
| **Touches** | new `src/liminal/server/policy.py`, `src/liminal/server/routes.py`, `src/liminal/server/app.py`, new admin router, `cli.py` |

---

## Purpose

The multi-issuer verifier authenticates *who* a caller is `(issuer, persona,
agent)`. This spec is the **authorization** half for a sovereign liminal: a
server-side policy table keyed on the verified `(issuer, persona)` that decides
*what they may do* — owned by the sovereign service, not by any caller's cabal —
plus the parent-only admin surface (`cbl federation …`) that manages it.

This introduces the liminal server's **first local persistent store**. Before it, the
server kept no database of its own (the memory handler's techne DB belongs to that
handler): credentials come from Cabal Core over HTTP
(`CabalCoreCredentialResolver`), handlers from entry points. A sovereign service
needs to remember its own grants, so it owns a small SQLite DB.

---

## 1. `PolicyStore`

New module `src/liminal/server/policy.py`, mirroring the resolver-injection pattern
of `credentials.py` (wired via `create_app`, stashed on `app.state`).

```python
@dataclass(frozen=True, slots=True)
class ScopeGrant:
    scopes: frozenset[str]                        # {"mem:query","mem:append","mem:synthesize","admin:*"}
    allowed_handlers: frozenset[str] | None = None  # None = every handler this service exposes

class PolicyStore(Protocol):
    async def resolve(self, issuer: str, persona: str) -> ScopeGrant | None: ...
    async def grant(self, issuer: str, persona: str, scopes: set[str],
                    allowed_handlers: set[str] | None) -> None: ...
    async def revoke(self, issuer: str, persona: str) -> None: ...
    async def list_grants(self) -> list[GrantRow]: ...
    async def audit(self, *, since: float | None, limit: int) -> list[AuditRow]: ...
    def parents(self) -> frozenset[str]: ...
```

### Resolution precedence

`resolve(issuer, persona)`: exact `(issuer, persona)` → issuer-wide `(issuer, "*")`
→ `None` (deny). Fail-closed — a missing or malformed grant denies, matching the
existing `_allowed_handlers_for` posture (`routes.py:225/230`).

### Schema — `SqlitePolicyStore`

```sql
CREATE TABLE policy_grants (
    issuer            TEXT NOT NULL,
    persona           TEXT NOT NULL,          -- "*" = issuer-wide
    scopes            TEXT NOT NULL,          -- JSON array
    allowed_handlers  TEXT,                   -- JSON array, or NULL = all
    is_parent         INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (issuer, persona)
);

CREATE TABLE policy_audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    issuer   TEXT, persona TEXT, agent TEXT,
    action   TEXT NOT NULL,   -- grant | revoke | access_allow | access_deny | admin
    detail   TEXT             -- JSON
);
```

### The parent invariant

At graduation the store is seeded with one row:
`(parent_issuer, "*", scopes⊇{"admin:*", …all data scopes}, is_parent=1)`.
`grant`/`revoke` **refuse to modify or delete any `is_parent=1` row** — the parent's
guardian standing cannot be revoked by anyone, including a second admin. `parents()`
returns the set of `is_parent=1` issuers (exactly one for v1). This is the code
expression of "graduation does not orphan."

---

## 2. Authorization inversion in `routes.py`

Guarded so single-cabal deployments (no `PolicyStore`) are untouched.

### `_authenticate` (routes.py:55)

```python
claims = await verifier.verify(token)
store = getattr(request.app.state, "policy_store", None)
if store is None:
    # single-cabal, today: trust token-embedded scope
    scope = claims.raw.get("cabal_scope") or claims.raw.get("scope")
    if not isinstance(scope, list) or "dispatch" not in scope:
        raise AuthError("dispatch scope required")
    return claims, None
# sovereign: ignore token-embedded scope; server-side policy is authoritative
grant = await store.resolve(claims.issuer, claims.identity)
if grant is None:
    await store.audit_access(claims, allowed=False, reason="no grant")
    raise AuthError(f"no policy grant for ({claims.issuer}, {claims.identity})")
return claims, grant
```

The grant rides alongside claims to the method handlers (thread it through the
existing `claims` plumbing, or stash on `request.state`).

### Method → scope

`tools/call` maps the target handler to a required scope
(`mem:append` handlers need `mem:append`, read handlers need `mem:query`, etc. — the
mapping table is derived from the persona's handler set, flagged open in the
multi-issuer spec). `admin/*` methods require `admin:*`. Deny → audit `access_deny`.

### `_allowed_handlers_for` (routes.py:210)

When a grant is present, return `grant.allowed_handlers` (server-authoritative),
**not** `claims.raw["tool_extras"]`. The token-embedded path stays for single-cabal.
`tools/list` (routes.py:190) already filters by this set, so a foreign caller only
ever *sees* what its grant permits.

---

## 3. `cbl federation` admin endpoints

A new admin router, mounted by `create_app` only when a `PolicyStore` is wired.
All routes require: authenticated via the multi-issuer verifier **and**
`claims.issuer in store.parents()` **and** the resolved grant contains `admin:*`
(the `parents()` check short-circuits before the store hit).

| Method | Route | `cbl` command | Body / query |
|---|---|---|---|
| POST | `/admin/policy/grant` | `cbl federation grant <svc> <issuer> --persona <p|*> --scope a,b` | `{issuer, persona, scopes[], allowed_handlers?}` |
| POST | `/admin/policy/revoke` | `cbl federation revoke <svc> <issuer> [--persona p]` | `{issuer, persona}` |
| GET | `/admin/policy` | `cbl federation ls <svc>` | — → list of grants |
| GET | `/admin/policy/audit` | `cbl federation audit <svc> --since 24h` | `?since=&limit=` |

`grant`/`revoke` reject any attempt to touch an `is_parent=1` row with HTTP 409.
Every mutation writes a `policy_audit` row (`action=grant|revoke`, `detail` = the
diff). `cbl` (cabal-side) authenticates these calls with a **parent token** minted
by the parent's Cabal Core (`aud=<service id>`, `iss=<parent cabal>`), i.e. the same
home-JWT path a data-plane call uses — the admin plane diverges only on the
server-side `admin:*` grant, never on a separate credential.

---

## 4. `create_app` + CLI wiring

`create_app` gains `policy_store: PolicyStore | None = None`; stashes
`app.state.policy_store` and mounts the admin router when present (mirrors how
`credential_resolver` is wired, `app.py:130`). CLI (`cli.py serve`) gains
`--policy-db <path>` → constructs `SqlitePolicyStore(path)`; presence of both
`--trust-registry` and `--policy-db` is what makes a deployment "sovereign."

`--policy-db` without `--trust-registry` is a config error (server-side policy with
a single-issuer verifier is nonsensical) — raise at `create_app` time, same style as
the `LIMINAL_AUTH_DISABLED` + verifier mutual-exclusion guard (`app.py:87`).

---

## 5. Test plan

1. **Precedence** — exact `(iss,persona)` beats `(iss,"*")`; no match → deny.
2. **Parent immutability** — `revoke`/`grant` on an `is_parent` row → refused; parent
   always resolves `admin:*`.
3. **Inversion** — foreign token with generous `tool_extras.allowed_handlers` but a
   `{mem:query}` grant → append denied, only query handlers listed (the core proof).
4. **Admin gate** — non-parent issuer with full data scope → 403 on `/admin/policy/*`;
   parent → 200.
5. **Audit** — grant/revoke and each access decision append audit rows; `--since`
   filters.
6. **Backward compat** — with no `policy_store`, `_authenticate`/`_allowed_handlers_for`
   behave exactly as today (regression over the existing suite).
7. **Config guard** — `--policy-db` without `--trust-registry` raises at startup.

---

## 6. Open items

- **Method→scope table** — shared with the multi-issuer spec; derive from the
  Archivist handler surface, don't hard-code.
- **Grant TTLs / expiry** — v1 grants are indefinite until revoked; time-boxed
  grants are a later nicety.
- **Audit as federated memory** — whether the audit log is itself queryable through
  the Archivist's own memory surface, or a separate store (design-doc open item).
- **Admin over A2A vs REST** — these are REST admin endpoints; if the sovereign
  service should also accept admin dispatches over A2A, that's additive later.
