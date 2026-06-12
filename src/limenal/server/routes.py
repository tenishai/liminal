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

import json as _json

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


async def _authenticate(
    verifier: JWTVerifier | None, authorization: str | None
) -> VerifiedClaims:
    token = _bearer(authorization)
    if token is None:
        raise AuthError("missing or malformed Authorization header")
    if verifier is None:
        raise AuthError(
            "this server has no JWT verifier configured — every request denied"
        )
    claims = await verifier.verify(token)
    # All authenticated limenal methods require dispatch scope.
    scope = claims.raw.get("cabal_scope")
    if not isinstance(scope, list) or "dispatch" not in scope:
        raise AuthError("dispatch scope required")
    return claims


def _to_spec_content(blocks: list[dict]) -> list[dict]:
    """Convert internal content blocks to MCP-spec types.

    limenal handlers use {"type": "json", "data": <dict>} for structured
    results — convenient for Python but not in the MCP spec (only text,
    image, resource are defined). Convert to {"type": "text", "text":
    json_string} so any strict third-party MCP client can parse the output.
    """
    out = []
    for block in blocks:
        if block.get("type") == "json":
            data = block.get("data", {})
            out.append({"type": "text", "text": _json.dumps(data, ensure_ascii=False)})
        else:
            out.append(block)
    return out


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
                claims = await _authenticate(request.app.state.jwt_verifier, authorization)
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
            return await _handle_tools_list(request, rpc_req, claims)
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
    request: Request,
    rpc_req: JSONRPCRequest,
    claims: VerifiedClaims | None,
) -> JSONRPCResponse:
    dispatcher: InProcessDispatcher = request.app.state.dispatcher
    tools = dispatcher.list_tools()
    allowed = _allowed_handlers_for(claims)
    # MCP camelCase: snake → camel for input_schema. Also filter by
    # per-persona allowed_handlers when set so the LLM never sees tools
    # its persona can't actually call (consistent with the credentials
    # isolation pattern: don't lie to the agent about what it can do).
    out = []
    for spec in tools:
        handler_name = spec["name"].split(".", 1)[0]
        if allowed is not None and handler_name not in allowed:
            continue
        adapted = {
            "name": spec["name"],
            "description": spec.get("description", ""),
            "inputSchema": spec.get("input_schema") or {"type": "object", "properties": {}},
        }
        out.append(adapted)
    result = ToolsListResult(tools=out)
    return make_success(id=rpc_req.id, result=result.model_dump(by_alias=True))


def _allowed_handlers_for(claims: VerifiedClaims | None) -> set[str] | None:
    """Extract the per-persona allowlist from the JWT claim.

    Returns None when there is no restriction (all handlers accessible).
    Returns an empty set when the claim is present but malformed or empty
    — fail closed so a broken claim denies all tools rather than opening
    up to everything.
    """
    if claims is None:
        return None
    extras = claims.raw.get("cabal_tool_extras")
    if extras is None:
        return None  # no tool_extras claim = unrestricted
    if not isinstance(extras, dict):
        return set()  # malformed: expected dict — deny all
    raw = extras.get("limenal.allowed_handlers")
    if raw is None:
        return None  # key absent = unrestricted
    if not isinstance(raw, list):
        return set()  # malformed: expected list — deny all
    return {str(h) for h in raw if isinstance(h, str) and h}


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

    # Per-persona handler allowlist check. tools/list already filters by
    # this list (Phase NN), but enforcing at tools/call too is the
    # defense-in-depth posture: an LLM that hallucinates a tool name
    # from training data shouldn't bypass the allowlist.
    handler_name = params.name.split(".", 1)[0]
    allowed = _allowed_handlers_for(claims)
    if allowed is not None and handler_name not in allowed:
        return make_error(
            id=rpc_req.id,
            code=ERROR_UNKNOWN_TOOL,
            message=(
                f"handler {handler_name!r} not in persona's allowed_handlers "
                f"({sorted(allowed)})"
            ),
        )

    # Credential resolver lookup. If none was wired, the handler gets {}
    # and either errors gracefully (slack, github) or works fine
    # (scratchpad). Phase 1.6 wires the real Cabal Core fetch.
    resolver = request.app.state.credential_resolver
    credentials: dict[str, str] = {}
    if resolver is not None:
        try:
            result = resolver(claims.identity, handler_name)
            # Accept both sync and async resolvers — production
            # CabalCoreCredentialResolver.fetch is async; in-process
            # tests / solo-mode adapters may be sync.
            import inspect

            if inspect.isawaitable(result):
                credentials = await result
            else:
                credentials = result
        except Exception as exc:  # noqa: BLE001
            log.warning("credential.resolve_failed", error=str(exc))
            return make_error(
                id=rpc_req.id,
                code=ERROR_INTERNAL,
                message=f"credential resolution failed: {exc}",
            )

    # cabal_tool_extras is a Cabal-Cabal channel: per-persona scoping
    # config (web.allowed_hosts, files.allowed_paths, memory.db_path,
    # etc.) embedded in the JWT by Cabal at mint time and forwarded into
    # Context.extra so handlers can read it the same way they do for tests.
    extra: dict = {}
    raw_extras = claims.raw.get("cabal_tool_extras")
    if isinstance(raw_extras, dict):
        extra = dict(raw_extras)

    ctx = Context(
        identity=claims.identity,
        agent_name=claims.agent_name,
        credentials=credentials,
        extra=extra,
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
        content=_to_spec_content(tool_result.content),
        isError=tool_result.is_error,
    )
    return make_success(id=rpc_req.id, result=result.model_dump(by_alias=True))
