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

import functools

import structlog
from fastapi import APIRouter, Header, Request, Response

from liminal import __version__
from liminal.dispatch import DispatchError, Multiplexer, UnknownTool
from liminal.protocol import Context
from liminal.server.auth import AuthError, JWTVerifier, VerifiedClaims
from liminal.server.mcp_types import (
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
from liminal.server.policy import PolicyStore, ScopeGrant
from liminal.server.scopes import DENY_SCOPE, OPERATOR_SCOPE
from liminal.server.secret_guard import scan_tool_call
from liminal.wire import to_spec_result_content as _to_spec_result_content

log = structlog.get_logger(__name__)


PUBLIC_METHODS = {"initialize", "ping", "notifications/initialized"}


def _token_scopes(claims: VerifiedClaims | None) -> list | None:
    """The verified token's own scope list: `cabal_scope`, falling back to
    `scope` so non-Cabal MCP clients (Claude Desktop, Cursor) work. Trusted
    only in single-cabal mode, where the token's issuer is the policy
    authority; never consult it when a grant is present."""
    if claims is None:
        return None
    scope = claims.raw.get("cabal_scope") or claims.raw.get("scope")
    return scope if isinstance(scope, list) else None


def _bearer(authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


async def _authenticate(
    verifier: JWTVerifier | None,
    authorization: str | None,
    policy_store: PolicyStore | None = None,
) -> tuple[VerifiedClaims, ScopeGrant | None]:
    token = _bearer(authorization)
    if token is None:
        raise AuthError("missing or malformed Authorization header")
    if verifier is None:
        raise AuthError(
            "this server has no JWT verifier configured — every request denied"
        )
    claims = await verifier.verify(token)

    if policy_store is None:
        # Single-cabal: the one trusted cabal is also the policy authority, so
        # trust its token-embedded scope. Accept `scope` as a fallback for
        # `cabal_scope` so non-Cabal MCP clients (Claude Desktop, Cursor) work.
        scope = _token_scopes(claims)
        if scope is None or "dispatch" not in scope:
            raise AuthError("dispatch scope required")
        return claims, None

    # Sovereign (multi-issuer): the caller's cabal is NOT the policy authority.
    # Ignore token-embedded scope/tool_extras; resolve server-side by the
    # verified (issuer, persona). No grant → deny (fail-closed) + audit.
    grant = await policy_store.resolve(claims.issuer, claims.identity)
    if grant is None:
        await policy_store.record_access(
            issuer=claims.issuer, persona=claims.identity,
            agent=claims.agent_name, allowed=False, detail={"reason": "no grant"},
        )
        raise AuthError(
            f"no policy grant for ({claims.issuer!r}, {claims.identity!r})"
        )
    return claims, grant


def build_router() -> APIRouter:
    router = APIRouter()

    @router.get("/healthz")
    async def healthz(request: Request) -> dict:
        # Per-target catalog status (liminal#75): a federated target whose
        # catalog fetch failed serves zero tools -- that must read as
        # "degraded" here, never as a healthy gateway with a quiet surface.
        # In-process targets carry no catalog_status and report "ready".
        # A target whose startup() raised reads "startup failed" (#86) ahead of
        # any catalog_status it managed to set before raising.
        dispatcher = getattr(request.app.state, "dispatcher", None)
        failed = getattr(dispatcher, "startup_failures", {}) if dispatcher else {}
        targets = {
            name: failed.get(name) or getattr(target, "catalog_status", "ready")
            for name, target in (dispatcher.targets if dispatcher else {}).items()
        }
        degraded = [n for n, s in targets.items() if s != "ready"]
        return {
            "status": "degraded" if degraded else "ok",
            "targets": targets,
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

        # Public methods skip auth (handshake + ping). Authenticated methods
        # also skip when LIMINAL_AUTH_DISABLED=1 — trusted-network mode for
        # solo/desktop deployments. The startup banner ensures the operator
        # knows this is on.
        claims: VerifiedClaims | None = None
        grant: ScopeGrant | None = None
        auth_disabled = getattr(request.app.state, "auth_disabled", False)
        if rpc_req.method not in PUBLIC_METHODS:
            if auth_disabled:
                # Synthesize claims so downstream Context construction works.
                # The identity is "anonymous" — handlers that genuinely care
                # about persona scoping should not be deployed in auth-
                # disabled mode in the first place.
                claims = VerifiedClaims(
                    identity="anonymous",
                    agent_name="anonymous",
                    raw={"scope": ["dispatch"]},
                    issuer="local",
                )
            else:
                try:
                    claims, grant = await _authenticate(
                        request.app.state.jwt_verifier,
                        authorization,
                        getattr(request.app.state, "policy_store", None),
                    )
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
            return await _handle_tools_list(request, rpc_req, claims, grant)
        if rpc_req.method == "tools/call":
            return await _handle_tools_call(request, rpc_req, claims, grant)

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
    grant: ScopeGrant | None = None,
) -> JSONRPCResponse:
    dispatcher: Multiplexer = request.app.state.dispatcher
    tools = await dispatcher.list_tools()
    allowed = _allowed_handlers_for(claims, grant)
    # MCP camelCase: snake → camel for input_schema. Filter by the same two
    # gates tools/call enforces -- the per-persona handler allowlist and, in
    # sovereign mode, the per-tool scope gate -- so what a persona sees is
    # exactly what those gates let it call (#61). Both checks are the
    # functions tools/call uses, so discovery cannot drift from them. Later
    # refusals (secret guard, handler-internal checks) depend on arguments
    # and are not visibility rules.
    out = []
    for spec in tools:
        handler_name = spec["name"].split(".", 1)[0]
        if allowed is not None and handler_name not in allowed:
            continue
        if _missing_scope(request, grant, spec["name"]) is not None:
            continue
        if _operator_refusal(request, claims, grant, spec["name"]) is not None:
            continue
        adapted = {
            "name": spec["name"],
            "description": spec.get("description", ""),
            "inputSchema": spec.get("input_schema") or {"type": "object", "properties": {}},
        }
        out.append(adapted)
    result = ToolsListResult(tools=out)
    # MCP spec: `nextCursor` is optional — OMIT it when there's no next page
    # rather than sending null. Strict clients (Claude Agent SDK Zod schema)
    # type it as `string | undefined` and reject an explicit null.
    return make_success(id=rpc_req.id, result=result.model_dump(by_alias=True, exclude_none=True))


def _missing_scope(
    request: Request, grant: ScopeGrant | None, tool_name: str
) -> str | None:
    """The scope `tool_name` requires that `grant` does not hold, or None.

    None means the scope gate admits the call: no grant (single-cabal and
    auth-disabled modes have no per-tool gate), no scope map wired, no
    requirement for this tool, or the requirement is held. Shared by
    tools/call (enforcement) and tools/list (discovery, #61).
    """
    if grant is None:
        return None
    scope_for = getattr(request.app.state, "policy_scope_for", None)
    required = scope_for(tool_name) if scope_for is not None else None
    if required and not grant.has_scope(required):
        return str(required)
    return None


def _operator_refusal(
    request: Request,
    claims: VerifiedClaims | None,
    grant: ScopeGrant | None,
    tool_name: str,
) -> str | None:
    """Why `tool_name` is refused as operator-only, or None if it may run.

    Runs in every mode, unlike `_missing_scope` (cabal#233):
    - auth-off: refused. There is no verified identity to be an operator.
    - sovereign (a grant is present): the GRANT must hold "operator" (admin:*
      satisfies it, per ScopeGrant.has_scope). The caller's token claims are
      ignored, so a foreign cabal cannot mint itself operator (liminal#22).
    - single-cabal (no grant): the verified token's cabal_scope (fallback
      `scope`) must hold "operator", alongside the "dispatch" auth requires.
    Shared by tools/call (enforcement) and tools/list (discovery).
    """
    operator_only = getattr(request.app.state, "operator_only", frozenset())
    if tool_name not in operator_only:
        return None
    if getattr(request.app.state, "auth_disabled", False):
        return (
            f"tool {tool_name!r} is operator-only and this server runs with "
            "auth disabled (LIMINAL_AUTH_DISABLED), so no caller can prove "
            "operator scope. Enable JWT auth to use it."
        )
    if grant is not None:
        if grant.has_scope(OPERATOR_SCOPE):
            return None
        return (
            f"tool {tool_name!r} is operator-only: the policy grant for this "
            f"caller must hold scope {OPERATOR_SCOPE!r}"
        )
    scope = _token_scopes(claims)
    if scope is not None and OPERATOR_SCOPE in scope:
        return None
    return (
        f"tool {tool_name!r} is operator-only: the token's cabal_scope must "
        f"hold {OPERATOR_SCOPE!r} as well as 'dispatch'"
    )


def _allowed_handlers_for(
    claims: VerifiedClaims | None, grant: ScopeGrant | None = None
) -> set[str] | None:
    """Resolve the per-caller handler allowlist.

    Returns None when there is no restriction (all handlers accessible).
    Returns an empty set when a restriction is present but empty/malformed
    — fail closed so a broken input denies all tools rather than opening up.

    Sovereign mode: when a server-side `grant` is present it is authoritative,
    and the token's own `tool_extras` is ignored — a foreign cabal cannot widen
    its own access by minting a generous allowlist claim. `grant.allowed_handlers
    is None` means all handlers; an empty set denies all.
    """
    if grant is not None:
        return None if grant.allowed_handlers is None else set(grant.allowed_handlers)
    if claims is None:
        return None
    # `tool_extras` is the standalone-friendly alias for `cabal_tool_extras`.
    extras = claims.raw.get("cabal_tool_extras") or claims.raw.get("tool_extras")
    if extras is None:
        return None  # no tool_extras claim = unrestricted
    if not isinstance(extras, dict):
        return set()  # malformed: expected dict — deny all
    raw = extras.get("liminal.allowed_handlers")
    if raw is None:
        return None  # key absent = unrestricted
    if not isinstance(raw, list):
        return set()  # malformed: expected list — deny all
    return {str(h) for h in raw if isinstance(h, str) and h}


async def _handle_tools_call(
    request: Request,
    rpc_req: JSONRPCRequest,
    claims: VerifiedClaims | None,
    grant: ScopeGrant | None = None,
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
    allowed = _allowed_handlers_for(claims, grant)
    if allowed is not None and handler_name not in allowed:
        if grant is not None:
            store = getattr(request.app.state, "policy_store", None)
            if store is not None:
                await store.record_access(
                    issuer=claims.issuer, persona=claims.identity,
                    agent=claims.agent_name, allowed=False,
                    detail={"handler": handler_name, "reason": "handler not allowed"},
                )
        return make_error(
            id=rpc_req.id,
            code=ERROR_UNKNOWN_TOOL,
            message=(
                f"handler {handler_name!r} not in persona's allowed_handlers "
                f"({sorted(allowed)})"
            ),
        )

    # Sovereign scope gate: when a grant and a scope map are wired, the scope
    # required by the specific TOOL must be held. `policy_scope_for` resolves
    # the full tool name "<target>.<tool>" — per-tool scope first, target-level
    # fallback — so a read/write split (memory recall vs commit) is enforceable,
    # not collapsed. The name covers BOTH in-process handlers, whose scopes come
    # from their CapabilityCards (liminal#26 handler-level, #42 per-tool), and
    # federated targets, whose scopes come from operator config (#78); the
    # Multiplexer namespaces them identically so this gate needs no branch.
    #
    # Three return states, not two: a scope string, None (no requirement), or
    # DENY_SCOPE for a tool on a deny-by-default target that no operator rule
    # names (#78). admin:* satisfies any of them (see ScopeGrant.has_scope).
    if grant is not None:
        required = _missing_scope(request, grant, params.name)
        if required is not None:
            store = getattr(request.app.state, "policy_store", None)
            if store is not None:
                await store.record_access(
                    issuer=claims.issuer, persona=claims.identity,
                    agent=claims.agent_name, allowed=False,
                    # The round-2 fix rewrote the WIRE string but left the
                    # audit row recording required_scope='liminal:deny'. Its own
                    # rationale -- naming the sentinel reads as an instruction
                    # to grant it -- applies verbatim to a structured field
                    # called `required_scope`, and that is the surface an
                    # operator triaging a denial actually greps.
                    # (Prudence, liminal#81 round 2.)
                    #
                    # `handler` matches the handler-allowlist deny above, so an
                    # audit consumer keyed on either field sees every denial
                    # (#44); `tool` keeps the per-tool granularity.
                    detail={
                        "handler": handler_name,
                        "tool": params.name,
                        **(
                            {"deny_reason": "not-in-scope-map"}
                            if required == DENY_SCOPE
                            else {"required_scope": required}
                        ),
                    },
                )
            # DENY_SCOPE is a sentinel, not a scope an operator should ever
            # grant. Naming it here would read as instructions: `has_scope` is
            # plain membership and the grant path validates nothing, so an
            # operator who "granted the scope the error asked for" would
            # silently open every unnamed tool on every strict target,
            # permanently. Say what actually happened instead.
            if required == DENY_SCOPE:
                message = (
                    f"tool {params.name!r} is not named in the scope map for "
                    f"target {handler_name!r}, which is deny-by-default because "
                    f"it declares tool_scopes. Add it to that target's "
                    f"[target.tool_scopes] table, or set a target-level "
                    f"required_scope. Do NOT grant {DENY_SCOPE!r} — it is a "
                    f"sentinel, and granting it disables this gate entirely."
                )
            else:
                message = f"scope {required!r} required for tool {params.name!r}"
            return make_error(
                id=rpc_req.id,
                code=ERROR_UNAUTHORIZED,
                message=message,
            )

    # Operator-only gate (cabal#233). Runs in every mode; see _operator_refusal.
    operator_refusal = _operator_refusal(request, claims, grant, params.name)
    if operator_refusal is not None:
        if grant is not None:
            store = getattr(request.app.state, "policy_store", None)
            if store is not None:
                await store.record_access(
                    issuer=claims.issuer, persona=claims.identity,
                    agent=claims.agent_name, allowed=False,
                    detail={
                        "handler": handler_name,
                        "tool": params.name,
                        "required_scope": OPERATOR_SCOPE,
                    },
                )
        log.warning(
            "operator_only.denied", tool=params.name,
            identity=claims.identity, issuer=claims.issuer,
        )
        return make_error(
            id=rpc_req.id, code=ERROR_UNAUTHORIZED, message=operator_refusal
        )

    # Fail-closed pre-persist secret guard (liminal#50): scan the content of
    # write-path tools before dispatch so a real key can't be persisted into the
    # corpus / a file / a notification. Placeholder forms are allowlisted in the
    # scanner. Runs after authz — nothing to scan on a call we'd already deny.
    if getattr(request.app.state, "secret_guard_enabled", True):
        try:
            secret_hits = scan_tool_call(params.name, params.arguments)
        except Exception as exc:  # noqa: BLE001 — fail closed on scanner error
            log.warning("secret_guard.scan_error", tool=params.name, error=str(exc))
            return make_error(
                id=rpc_req.id,
                code=ERROR_INVALID_PARAMS,
                message="secret guard scan failed; refusing to persist (fail-closed)",
            )
        if secret_hits:
            log.warning(
                "secret_guard.blocked", tool=params.name, hit_types=secret_hits
            )
            return make_error(
                id=rpc_req.id,
                code=ERROR_INVALID_PARAMS,
                message=(
                    f"refused: {params.name!r} content matched secret pattern(s) "
                    f"{secret_hits} — remove the secret or use a placeholder "
                    f"(REDACTED / ${{VAR}}). Set LIMINAL_SECRET_GUARD=0 to disable."
                ),
            )

    # Credential resolver lookup. If none was wired, the handler gets {}
    # and either errors gracefully (slack, github) or works fine
    # (scratchpad). Phase 1.6 wires the real Cabal Core fetch.
    #
    # Cabal's secrets path is /admin/secrets/{persona}/{handler} with no issuer
    # (credentials.py), and a foreign issuer can mint any persona name, so in
    # sovereign mode only the parent issuer's callers reach the resolver
    # (liminal#143). A grant-authorized call from any other issuer gets {}: a
    # service-token HTTP target then refuses (target/http.py), and notify's
    # webhook falls back to the operator's policy_tool_extras URL or refuses.
    # "The parent" is the policy store's parents(): the same source the admin
    # guardian gate uses (admin.py), and the store refuses to open when its
    # parent rows disagree with the configured parent issuer
    # (_reconcile_parent_issuers). No grant (single-cabal, auth-off) keeps the
    # unconditional two-argument call.
    resolver = request.app.state.credential_resolver
    credentials: dict[str, str] = {}
    resolver_kwargs: dict[str, str] = {}
    if grant is not None:
        store = getattr(request.app.state, "policy_store", None)
        if store is None or claims.issuer not in store.parents():
            log.info(
                "credential.skipped_non_parent_issuer",
                issuer=claims.issuer, persona=claims.identity, handler=handler_name,
            )
            resolver = None
        else:
            resolver_kwargs = {"issuer": claims.issuer}
    if resolver is not None:
        try:
            credentials = await resolver(
                claims.identity, handler_name, **resolver_kwargs
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("credential.resolve_failed", error=str(exc))
            return make_error(
                id=rpc_req.id,
                code=ERROR_INTERNAL,
                message=f"credential resolution failed: {exc}",
            )

    # tool_extras carries per-persona SANDBOX config (memory.db_path,
    # files.allowed_paths, web/notify.allowed_hosts, ...) that bounds where a
    # handler may operate. In SOVEREIGN mode (a grant is present) the caller's
    # cabal is NOT trusted, so its token-embedded tool_extras is IGNORED —
    # otherwise a foreign token could pick which persona's memory DB / paths /
    # egress a granted handler uses (the tenant-isolation seam). The sovereign
    # service supplies these boundaries itself via `policy_tool_extras`
    # (operator-configured), never the token. Single-cabal keeps the trusted
    # token-embedded path (its issuer is also the policy authority).
    extra: dict = {}
    if grant is not None:
        server_extra = getattr(request.app.state, "policy_tool_extras", None)
        if isinstance(server_extra, dict):
            extra = dict(server_extra)
    else:
        raw_extras = claims.raw.get("cabal_tool_extras") or claims.raw.get("tool_extras")
        if isinstance(raw_extras, dict):
            extra = dict(raw_extras)

    # Accept an inbound correlation id for end-to-end tracing across the
    # multiplexer→target hop (a fresh one is generated downstream if absent).
    # It's a trace tag, not sandbox config or an authz input, so it's threaded
    # regardless of grant — closing the inbound half of #27.
    inbound_cid = request.headers.get("x-correlation-id")
    if inbound_cid:
        # Clamp — a caller-supplied trace tag shouldn't flow unbounded into
        # structured logs or the outbound x-correlation-id hop.
        extra["correlation_id"] = inbound_cid[:200]

    # Handler-level authorization inputs (#108). Both exist only in sovereign
    # mode (a grant is present): `granted_scopes` comes from the policy grant,
    # never the token's own scope claim (same rule as _allowed_handlers_for),
    # and `audit` writes to the same store the gates above record to. Under
    # auth-off a wired store is inert (app.py), so it gets no audit rows either.
    audit = None
    store = getattr(request.app.state, "policy_store", None)
    if grant is not None and store is not None:
        audit = functools.partial(
            store.record_access,
            issuer=claims.issuer,
            persona=claims.identity,
            agent=claims.agent_name,
        )

    ctx = Context(
        identity=claims.identity,
        agent_name=claims.agent_name,
        credentials=credentials,
        issuer=claims.issuer,
        extra=extra,
        granted_scopes=grant.scopes if grant is not None else frozenset(),
        audit=audit,
    )

    dispatcher: Multiplexer = request.app.state.dispatcher
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
        content=_to_spec_result_content(
            tool_result.content,
            is_error=tool_result.is_error,
            error=tool_result.error,
        ),
        isError=tool_result.is_error,
    )
    payload = result.model_dump(by_alias=True)
    # #79 — an untrusted target flags its own results at the boundary that
    # knows the trust tier; the route only forwards that out-of-band. `_meta`
    # is the MCP-sanctioned place for it, and it carries the envelope nonce so
    # a runtime can verify the in-band delimiters rather than pattern-matching
    # text an upstream could imitate.
    if getattr(tool_result, "liminal_untrusted", False):
        payload["_meta"] = {
            "liminal/untrusted": True,
            "liminal/untrusted_source": getattr(
                tool_result, "liminal_untrusted_source", None
            ),
            "liminal/untrusted_nonce": getattr(
                tool_result, "liminal_untrusted_nonce", None
            ),
        }
    return make_success(id=rpc_req.id, result=payload)
