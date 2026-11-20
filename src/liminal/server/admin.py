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

from liminal.handlers import aws as aws_handler
from liminal.registry import Registry
from liminal.server.auth import AuthError, VerifiedClaims
from liminal.server.live_targets import FileOwned, LiveTargetError, LiveTargets, UnknownLiveTarget
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


class AwsProbeBody(BaseModel):
    role_arn: str
    audience: str = aws_handler.DEFAULT_AUDIENCE


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

    # ---- live targets (liminal#222) ------------------------------------------
    # Federated targets added, replaced and removed while serving, persisted in
    # the policy DB; the config file stays the seed and keeps its names.

    def _live(request: Request) -> LiveTargets:
        live = getattr(request.app.state, "live_targets", None)
        if live is None or not live.attached:
            raise HTTPException(
                status_code=404,
                detail="live targets are not enabled on this gateway (they need --policy-db)",
            )
        return live

    @router.get("/admin/targets")
    async def list_targets(
        request: Request, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        await _admin_auth(request, authorization)
        return {"targets": _live(request).list()}

    @router.put("/admin/targets/{name}")
    async def put_target(
        name: str, request: Request, body: dict[str, Any],
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        claims, _store = await _admin_auth(request, authorization)
        live = _live(request)
        try:
            status = await live.put(name, body)
        except FileOwned as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except LiveTargetError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        log.info("admin.target_put", target=name, status=status, by=claims.identity)
        return {"name": name, "status": status}

    @router.delete("/admin/targets/{name}")
    async def delete_target(
        name: str, request: Request, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        claims, _store = await _admin_auth(request, authorization)
        live = _live(request)
        try:
            await live.delete(name)
        except FileOwned as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except UnknownLiveTarget as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        log.info("admin.target_removed", target=name, by=claims.identity)
        return {"removed": name}

    @router.get("/admin/aws/identity")
    async def aws_identity(
        request: Request,
        audience: str = aws_handler.DEFAULT_AUDIENCE,
        authorization: str | None = Header(default=None),
    ) -> dict[str, str]:
        """The gateway's own Google identity, as an account owner's trust
        policy must name it: issuer, subject (the service account's unique
        id) and the audience the token carries. Read from a token minted
        for the purpose; the token itself never leaves the gateway."""
        await _admin_auth(request, authorization)
        try:
            token = await aws_handler.web_identity_token(audience)
            return aws_handler.identity_from_token(token)
        except aws_handler.AwsError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @router.post("/admin/aws/probe")
    async def aws_probe(
        request: Request, body: AwsProbeBody, authorization: str | None = Header(default=None)
    ) -> dict[str, str]:
        """Assume a role once as the room, so a set-up page can say
        "connected" only after AWS has agreed."""
        claims, _store = await _admin_auth(request, authorization)
        try:
            return await aws_handler.probe(body.role_arn, body.audience, who=claims.identity)
        except aws_handler.AwsError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.get("/admin/cards")
    async def cards(
        request: Request, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        """Every loaded handler's capability card, under the name a grant's
        `allowed_handlers` and a tool name use. Fields a handler adds beside
        the schema's (card `labels`, a tool's `permissions` or `risk`) come
        back as written, so a governing service can derive what a grant
        opens from the handlers themselves instead of a table of its own.
        Federated targets are not handlers; `GET /admin/targets` lists them.
        Never an empty list for "unknown": an admin plane built without the
        registry answers 404, so a reader keeps what it knew."""
        await _admin_auth(request, authorization)
        registry: Registry | None = getattr(request.app.state, "registry", None)
        if registry is None:
            raise HTTPException(
                status_code=404,
                detail="handler cards are not served by this admin plane (it was built without the registry)",
            )
        return {
            "cards": [
                {"name": record.name, "card": record.card.model_dump(mode="json")}
                for record in sorted(registry, key=lambda r: r.name)
            ]
        }

    @router.get("/admin/policy/audit")
    async def audit(
        request: Request,
        since: float | None = None,
        limit: int = 100,
        persona: str | None = None,
        agent: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _claims, store = await _admin_auth(request, authorization)
        rows = await store.audit(since=since, limit=min(max(limit, 1), 1000), persona=persona, agent=agent)
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
