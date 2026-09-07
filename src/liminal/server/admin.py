"""Federation admin surface for a sovereign liminal — the parent's guardian plane.

Mounted by `create_app` only when a `PolicyStore` is wired. Every route requires a
token from a **parent** issuer carrying `admin:*` (federated-singletons.md): the
parent manages the third-party allowlist without a separate credential — same
home-JWT path as the data plane, diverging only on the server-side `admin:*` grant.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from liminal.server.auth import AuthError, VerifiedClaims
from liminal.server.policy import ADMIN_SCOPE, ParentImmutable, PolicyStore
from liminal.server.routes import _bearer

log = structlog.get_logger(__name__)


class GrantBody(BaseModel):
    issuer: str
    persona: str = "*"
    scopes: list[str]
    allowed_handlers: list[str] | None = None


class RevokeBody(BaseModel):
    issuer: str
    persona: str = "*"


async def _admin_auth(
    request: Request, authorization: str | None
) -> tuple[VerifiedClaims, PolicyStore]:
    verifier = getattr(request.app.state, "jwt_verifier", None)
    store: PolicyStore | None = getattr(request.app.state, "policy_store", None)
    if verifier is None or store is None:
        raise HTTPException(status_code=404, detail="federation admin not enabled")
    token = _bearer(authorization)
    if token is None:
        raise HTTPException(status_code=401, detail="missing bearer token")
    try:
        claims = await verifier.verify(token)
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    # Parent guardian gate: issuer must be a parent AND this persona must hold
    # a parent row with admin:*. Resolution goes through resolve_parent --
    # never the data-plane resolve(), which excludes parent rows (liminal#73):
    # when the parent issuer also signs agent tokens, an agent's data-plane
    # grant must never add up to admin standing, and a wildcard parent row is
    # an explicit deployment choice, not a fallback.
    if claims.issuer not in store.parents():
        raise HTTPException(status_code=403, detail="admin requires a parent issuer")
    grant = await store.resolve_parent(claims.issuer, claims.identity)
    if grant is None or not grant.has_scope(ADMIN_SCOPE):
        raise HTTPException(status_code=403, detail="admin:* scope required")
    return claims, store


def build_admin_router() -> APIRouter:
    router = APIRouter()

    @router.post("/admin/policy/grant")
    async def grant(
        request: Request, body: GrantBody, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        _claims, store = await _admin_auth(request, authorization)
        try:
            await store.grant(
                body.issuer,
                body.persona,
                scopes=set(body.scopes),
                allowed_handlers=(
                    set(body.allowed_handlers) if body.allowed_handlers is not None else None
                ),
            )
        except ParentImmutable as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"status": "ok", "issuer": body.issuer, "persona": body.persona}

    @router.post("/admin/policy/revoke")
    async def revoke(
        request: Request, body: RevokeBody, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        _claims, store = await _admin_auth(request, authorization)
        try:
            await store.revoke(body.issuer, body.persona)
        except ParentImmutable as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"status": "ok"}

    @router.get("/admin/policy")
    async def ls(
        request: Request, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        _claims, store = await _admin_auth(request, authorization)
        rows = await store.list_grants()
        return {
            "grants": [
                {
                    "issuer": r.issuer,
                    "persona": r.persona,
                    "scopes": sorted(r.scopes),
                    "allowed_handlers": (
                        sorted(r.allowed_handlers) if r.allowed_handlers is not None else None
                    ),
                    "is_parent": r.is_parent,
                }
                for r in rows
            ]
        }

    @router.get("/admin/policy/audit")
    async def audit(
        request: Request,
        since: float | None = None,
        limit: int = 100,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _claims, store = await _admin_auth(request, authorization)
        rows = await store.audit(since=since, limit=limit)
        return {
            "audit": [
                {
                    "ts": r.ts,
                    "action": r.action,
                    "issuer": r.issuer,
                    "persona": r.persona,
                    "agent": r.agent,
                    "detail": r.detail,
                }
                for r in rows
            ]
        }

    return router
