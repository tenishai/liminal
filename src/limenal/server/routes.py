"""POST /mcp route — the JSON-RPC entry point.

Method dispatch is a small switch:
    initialize                  → InitializeResult
    notifications/initialized   → ignored (one-way); returns 202
    ping                        → echo
    tools/list                  → dispatcher.list_tools() shaped as ToolsListResult
    tools/call                  → dispatcher.dispatch() → ToolCallResult

Bearer auth applies to all methods except `initialize` and `ping` so a
client that doesn't yet have a token can still complete the handshake.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Header, Request, Response

from limenal import __version__
from limenal.dispatch import DispatchError, InProcessDispatcher, UnknownTool
from limenal.protocol import Context
from limenal.server.auth import AuthError, JWTVerifier, VerifiedClaims
from limenal.server.mcp_types import (
    ERROR_INTERNAL,
    ERROR_INVALID_PARAMS,
    ERROR_INVALID_REQUEST,
    ERROR_METHOD_NOT_FOUND,
    ERROR_UNAUTHORIZED,
    ERROR_UNKNOWN_TOOL,
    InitializeParams,
    InitializeResult,
    JSONRPCRequest,
    JSONRPCResponse,
    ServerInfo,
    ToolCallParams,
    ToolCallResult,
    ToolsListResult,
    make_error,
    make_success,
)

log = structlog.get_logger(__name__)


PUBLIC_METHODS = {"initialize", "ping", "notifications/initialized"}


def _bearer(authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


def _authenticate(
    verifier: JWTVerifier | None, authorization: str | None
) -> VerifiedClaims:
    token = _bearer(authorization)
    if token is None:
        raise AuthError("missing or malformed Authorization header")
    if verifier is None:
        raise AuthError(
            "this server has no JWT verifier configured — every request denied"
        )
    return verifier.verify(token)


def build_router() -> APIRouter:
    router = APIRouter()

    @router.get("/healthz")
    async def healthz(request: Request) -> dict:
        reg = request.app.state.registry
        return {
            "status": "ok",
            "version": __version__,
            "handlers": reg.names() if reg else [],
        }

    @router.post("/mcp", response_model=None)
    async def mcp(
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ):
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return make_error(
                id=None,
                code=ERROR_INVALID_REQUEST,
                message="request body is not JSON",
            )

        try:
            rpc_req = JSONRPCRequest.model_validate(body)
        except Exception as exc:  # noqa: BLE001
            return make_error(
                id=body.get("id") if isinstance(body, dict) else None,
                code=ERROR_INVALID_REQUEST,
                message=f"invalid JSON-RPC envelope: {exc}",
            )

        # `notifications/*` per JSON-RPC are one-way — no response body. We
        # return 202 with an empty body so clients that wait on a response
        # don't hang.
        if rpc_req.method.startswith("notifications/"):
            response.status_code = 202
            return Response(status_code=202)

        # Public methods skip auth (handshake + ping)
        claims: VerifiedClaims | None = None
        if rpc_req.method not in PUBLIC_METHODS:
            try:
                claims = _authenticate(request.app.state.jwt_verifier, authorization)
            except AuthError as exc:
                return make_error(
                    id=rpc_req.id,
                    code=ERROR_UNAUTHORIZED,
                    message=str(exc),
                )

        if rpc_req.method == "initialize":
            return await _handle_initialize(request, rpc_req)
        if rpc_req.method == "ping":
            return make_success(id=rpc_req.id, result={})
        if rpc_req.method == "tools/list":
            return await _handle_tools_list(request, rpc_req)
        if rpc_req.method == "tools/call":
            return await _handle_tools_call(request, rpc_req, claims)

        return make_error(
            id=rpc_req.id,
            code=ERROR_METHOD_NOT_FOUND,
            message=f"unknown method: {rpc_req.method!r}",
        )

    return router


# ---- method handlers ------------------------------------------------------


async def _handle_initialize(
    request: Request, rpc_req: JSONRPCRequest
) -> JSONRPCResponse:
    try:
        params = InitializeParams.model_validate(rpc_req.params or {})
    except Exception as exc:  # noqa: BLE001
        return make_error(
            id=rpc_req.id,
            code=ERROR_INVALID_PARAMS,
            message=f"invalid initialize params: {exc}",
        )
    result = InitializeResult(
        protocolVersion=params.protocolVersion,
        serverInfo=ServerInfo(
            name=request.app.state.server_name, version=__version__
        ),
        capabilities={"tools": {"listChanged": False}},
    )
    return make_success(id=rpc_req.id, result=result.model_dump(by_alias=True))


async def _handle_tools_list(
    request: Request, rpc_req: JSONRPCRequest
) -> JSONRPCResponse:
    dispatcher: InProcessDispatcher = request.app.state.dispatcher
    tools = dispatcher.list_tools()
    # MCP camelCase: snake → camel for input_schema
    out = []
    for spec in tools:
        adapted = {
            "name": spec["name"],
            "description": spec.get("description", ""),
            "inputSchema": spec.get("input_schema") or {"type": "object", "properties": {}},
        }
        out.append(adapted)
    result = ToolsListResult(tools=out)
    return make_success(id=rpc_req.id, result=result.model_dump(by_alias=True))


async def _handle_tools_call(
    request: Request, rpc_req: JSONRPCRequest, claims: VerifiedClaims | None
) -> JSONRPCResponse:
    if claims is None:
        # Shouldn't happen because PUBLIC_METHODS gated it, but defend.
        return make_error(
            id=rpc_req.id, code=ERROR_UNAUTHORIZED, message="missing claims"
        )
    try:
        params = ToolCallParams.model_validate(rpc_req.params or {})
    except Exception as exc:  # noqa: BLE001
        return make_error(
            id=rpc_req.id,
            code=ERROR_INVALID_PARAMS,
            message=f"invalid tools/call params: {exc}",
        )

    # Credential resolver lookup. If none was wired, the handler gets {}
    # and either errors gracefully (slack, github) or works fine
    # (scratchpad). Phase 1.6 wires the real Cabal Core fetch.
    resolver = request.app.state.credential_resolver
    handler_name = params.name.split(".", 1)[0]
    credentials: dict[str, str] = {}
    if resolver is not None:
        try:
            credentials = resolver(claims.identity, handler_name)
        except Exception as exc:  # noqa: BLE001
            log.warning("credential.resolve_failed", error=str(exc))
            return make_error(
                id=rpc_req.id,
                code=ERROR_INTERNAL,
                message=f"credential resolution failed: {exc}",
            )

    ctx = Context(
        identity=claims.identity,
        agent_name=claims.agent_name,
        credentials=credentials,
    )

    dispatcher: InProcessDispatcher = request.app.state.dispatcher
    try:
        tool_result = await dispatcher.dispatch(
            tool_name=params.name, payload=params.arguments, ctx=ctx
        )
    except UnknownTool as exc:
        return make_error(
            id=rpc_req.id,
            code=ERROR_UNKNOWN_TOOL,
            message=str(exc),
        )
    except DispatchError as exc:
        return make_error(
            id=rpc_req.id,
            code=ERROR_INVALID_PARAMS,
            message=str(exc),
        )

    result = ToolCallResult(
        content=tool_result.content,
        isError=tool_result.is_error,
    )
    return make_success(id=rpc_req.id, result=result.model_dump(by_alias=True))
