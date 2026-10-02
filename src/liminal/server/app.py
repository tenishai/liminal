"""FastAPI app factory.

Wires the registry → dispatcher → MCP route. Auth is injectable so tests
can pass a StaticKeySetVerifier and production wires URLJWKSVerifier
against Cabal Core.

Trusted-network deployments (Claude Desktop talking to localhost, a
script wrapping liminal in a single-operator environment) can disable
JWT enforcement entirely by setting `LIMINAL_AUTH_DISABLED=1`. A loud
WARN banner fires at startup so the mode can't ship to prod by
accident; a JWT verifier supplied alongside the env var is a
configuration error and raises at create_app time.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI

from liminal import __version__
from liminal.dispatch import Multiplexer
from liminal.registry import Registry, discover_handlers
from liminal.server.admin import build_admin_router
from liminal.server.auth import JWTVerifier, MultiIssuerJWKSVerifier
from liminal.server.policy import PolicyStore
from liminal.server.routes import build_router
from liminal.server.scopes import DENY_SCOPE
from liminal.target import (
    InProcessTarget,
    Target,
    TargetSpec,
    build_http_targets,
)

log = structlog.get_logger(__name__)


_AUTH_DISABLED_ENV = "LIMINAL_AUTH_DISABLED"
_AUTH_DISABLED_TRUTHY = {"1", "true", "yes", "on"}


def _auth_disabled_from_env() -> bool:
    """Returns True iff LIMINAL_AUTH_DISABLED is set to a truthy value."""
    return os.environ.get(_AUTH_DISABLED_ENV, "").lower() in _AUTH_DISABLED_TRUTHY


_SECRET_GUARD_ENV = "LIMINAL_SECRET_GUARD"
_SECRET_GUARD_FALSEY = {"0", "false", "no", "off"}


def _secret_guard_enabled_from_env() -> bool:
    """Fail-closed secret guard is ON by default (liminal#50).

    Disable per-deployment with a falsey ``LIMINAL_SECRET_GUARD`` (0/false/no/off).
    """
    return os.environ.get(_SECRET_GUARD_ENV, "").strip().lower() not in _SECRET_GUARD_FALSEY


class ConfigError(RuntimeError):
    """A build-time operator-configuration mistake raised by ``create_app``.

    Subclasses ``RuntimeError`` for back-compat with any existing ``except
    RuntimeError`` — but having a distinct type lets ``cli.main()`` catch it at
    the boundary and render ``error: <cause>`` with exit 2, honouring the
    "config errors never surface as a traceback" contract (liminal#31).
    """


def scope_for_from_registry(reg: Registry) -> Callable[[str], str | None]:
    """Back-compat wrapper: the handler-only resolver (no federated targets)."""
    return scope_for(reg, ())


def scope_for(
    reg: Registry, targets: Sequence[TargetSpec] = ()
) -> Callable[[str], str | None]:
    """Derive the required-scope resolver for the whole tool surface.

    Two sources, keyed identically as ``<target>`` and ``<target>.<tool>``,
    because the Multiplexer already namespaces in-process handlers and
    federated upstreams the same way:

    - **In-process handlers** — from each ``CapabilityCard`` (liminal#26
      handler-level, #42 per-tool). Trusted because handler code is
      server-side.
    - **Federated targets** — from ``TargetSpec.required_scope`` /
      ``TargetSpec.tool_scopes`` (liminal#78). OPERATOR-authored, never read
      from the fetched catalog: an untrusted upstream that could declare its
      own required scopes would simply declare that it needs none.

    Resolution order for a full tool name: exact ``<target>.<tool>`` rule,
    then the target-level rule, then ``DENY_SCOPE`` if that target is
    deny-by-default (it declared ``tool_scopes``), else ``None`` (open).

    Target names cannot collide with handler names — ``create_app`` rejects
    that at build time — so one flat map is unambiguous.
    """
    scope_map: dict[str, str] = {}
    strict_targets: set[str] = set()

    for record in reg:
        card = record.card
        if card.required_scope:
            scope_map[record.name] = card.required_scope
        for tool in card.tools:
            tool_scope = getattr(tool, "required_scope", None)
            if tool_scope:
                scope_map[f"{record.name}.{tool.name}"] = tool_scope

    for spec in targets:
        if spec.required_scope:
            scope_map[spec.name] = spec.required_scope
        for tool_name, tool_scope in spec.tool_scopes.items():
            scope_map[f"{spec.name}.{tool_name}"] = tool_scope
        # Naming ANY per-tool rule opts this target into deny-by-default, so a
        # tool that appears in a refreshed upstream catalog cannot arrive
        # pre-authorized.
        if spec.tool_scopes:
            strict_targets.add(spec.name)

    def _scope_for(
        name: str,
        _sm: dict[str, str] = scope_map,
        _strict: set[str] = strict_targets,
    ) -> str | None:
        # `name` is a full tool name "<target>.<tool>" (the tools/call path)
        # or a bare target/handler. Per-tool rule wins; else the target-level
        # rule; else deny when the target is deny-by-default.
        if name in _sm:
            return _sm[name]
        prefix = name.split(".", 1)[0]
        if prefix in _sm:
            return _sm[prefix]
        if prefix in _strict:
            return DENY_SCOPE
        return None

    return _scope_for


def operator_only_tools(reg: Registry) -> frozenset[str]:
    """Full names ``<handler>.<tool>`` of every in-process tool whose card
    entry sets ``requires_operator`` (cabal#233).

    Built from the same validated ``CapabilityCard`` the scope map reads, so a
    handler discovered through entry points carries the flag into the gate.
    Federated targets have no such flag: their catalogs are untrusted and
    their gating is operator config (``TargetSpec``), as with scopes.
    """
    return frozenset(
        f"{record.name}.{tool.name}"
        for record in reg
        for tool in record.card.tools
        if tool.requires_operator
    )


def create_app(
    *,
    jwt_verifier: JWTVerifier | None = None,
    registry: Registry | None = None,
    credential_resolver: Callable[[str, str], Awaitable[dict[str, str]]] | None = None,
    server_name: str = "liminal",
    targets: list[TargetSpec] | None = None,
    policy_store: PolicyStore | None = None,
    policy_scope_for: Callable[[str], str | None] | None = None,
    policy_tool_extras: dict[str, Any] | None = None,
    mount_admin: bool = True,
) -> FastAPI:
    """Build a FastAPI MCP server.

    Args:
        jwt_verifier: required at request time; if None, the /mcp route
            rejects every request with -32001. Tests pass a
            StaticKeySetVerifier; production wires URLJWKSVerifier.
        registry: pre-populated registry; if None, discover via entry-points.
        credential_resolver: (persona, handler) → credentials dict. Optional;
            when None the Context.credentials passed to handlers is {} (the
            handler had better be one that doesn't need credentials, like
            scratchpad). Phase 1.6 will swap a real Cabal Core fetcher in
            via this hook.
        server_name: the name reported by the `initialize` handshake.
        targets: optional list of ``TargetSpec`` describing federated
            upstream MCP servers (``transport="http"`` in Stage A). Each
            becomes an ``HttpTarget`` in the Multiplexer under its ``name``,
            namespacing the upstream's tools as ``"{name}.{tool}"``. The
            lifespan connects, initializes, fetches + inspects each catalog,
            and forwards calls with per-call persona identity. Used for
            persona graduation (a cabal persona moving to its own container)
            and third-party MCP integration (Jira, Slack, GitHub, etc.).
    """

    # Resolve the registry once; lifespan closes over it.
    reg = registry if registry is not None else discover_handlers()

    # Every in-process handler becomes an InProcessTarget; every configured
    # federated upstream becomes an HttpTarget. Both plug into the same
    # Multiplexer behind the identical public surface ({target}.{tool}
    # prefixing + dispatch signature) — the federation authz seam is unchanged.
    all_targets: list[Target] = [
        InProcessTarget(name=record.name, handler=record.handler)
        for record in reg
    ]
    if targets:
        # Reject any target name that collides with an in-process handler (or
        # another target) — loud, per No Silent Failures.
        all_targets.extend(
            build_http_targets(targets, reserved_names=set(reg.names()))
        )

    dispatcher = Multiplexer(all_targets)

    auth_disabled = _auth_disabled_from_env()
    if auth_disabled and jwt_verifier is not None:
        raise ConfigError(
            f"liminal misconfiguration: {_AUTH_DISABLED_ENV}=1 is set but a "
            "JWT verifier was passed to create_app(). These are mutually "
            "exclusive — pick one. Set the env var only for trusted-network "
            "deployments (single operator, localhost client)."
        )

    # Sovereign safety invariant: a multi-issuer verifier trusts several cabals,
    # so it MUST NOT run on the token-embedded authz path — that would let any
    # federated cabal self-grant scope via its own scope/tool_extras claims.
    # A PolicyStore (server-side authorization) is required alongside it.
    if isinstance(jwt_verifier, MultiIssuerJWKSVerifier) and policy_store is None:
        raise ConfigError(
            "liminal misconfiguration: a MultiIssuerJWKSVerifier requires a "
            "policy_store. Without server-side authorization, a federated cabal "
            "could self-grant scope through its own token claims. Wire a "
            "PolicyStore (e.g. SqlitePolicyStore) into create_app()."
        )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        log.info("liminal.startup", version=__version__, handlers=reg.names())
        if auth_disabled:
            # Loud banner so this can't ship to prod without someone seeing it.
            log.warning(
                "liminal.AUTH_DISABLED",
                msg=(
                    "JWT enforcement disabled via LIMINAL_AUTH_DISABLED. Every "
                    "request will be accepted. Only use this for trusted-network "
                    "deployments (single operator, localhost client). UNSET in "
                    "production."
                ),
            )
        # Start every target (in registration order). InProcessTarget
        # delegates to its handler's startup() when defined (e.g. to open
        # pooled clients); HttpTarget connects + fetches its catalog.
        await dispatcher.startup()
        yield
        # Shut down in reverse registration order.
        await dispatcher.shutdown()
        log.info("liminal.shutdown")

    app = FastAPI(
        title="liminal MCP gateway",
        version=__version__,
        lifespan=lifespan,
    )

    app.state.registry = reg
    app.state.dispatcher = dispatcher
    app.state.jwt_verifier = jwt_verifier
    app.state.credential_resolver = credential_resolver
    app.state.server_name = server_name
    app.state.auth_disabled = auth_disabled
    app.state.secret_guard_enabled = _secret_guard_enabled_from_env()
    app.state.policy_store = policy_store
    # Scope map has two sources, both server-side: each CapabilityCard's
    # required_scope for in-process handlers (liminal#26/#42), and each
    # TargetSpec's required_scope/tool_scopes for federated targets
    # (liminal#78 — operator-authored, never read from the fetched catalog).
    # An explicit policy_scope_for (tests) still overrides both.
    # NOTE: this is a populated callable even in single-cabal mode, but it is
    # inert there — the routes.py scope gate only runs when a grant is present,
    # which only sovereign (multi-issuer + policy_store) deployments produce.
    app.state.policy_scope_for = (
        policy_scope_for if policy_scope_for is not None
        else scope_for(reg, targets or ())
    )
    # Operator-only tools (cabal#233). Unlike the scope map this gate runs in
    # EVERY mode, so it is not inert in single-cabal: see routes._operator_refusal.
    app.state.operator_only = operator_only_tools(reg)
    # Server-supplied sandbox config (memory.db_path, files.allowed_paths,
    # egress allowlists) for sovereign mode. Used INSTEAD of the caller's
    # token tool_extras when a grant is present — the token never picks a
    # handler's operating boundary in a federated deployment.
    app.state.policy_tool_extras = policy_tool_extras

    # A wired policy store that can never run (auth disabled) is almost
    # certainly a misconfiguration — the sovereign authz path is silently
    # inert. Warn loudly rather than fail (trusted-network mode is valid).
    if auth_disabled and policy_store is not None:
        log.warning(
            "liminal.policy_store_inert",
            msg=(
                "a policy_store is wired but LIMINAL_AUTH_DISABLED=1 — sovereign "
                "authorization is bypassed (anonymous claims, no policy resolve)."
            ),
        )

    app.include_router(build_router())
    # Federation admin surface is only reachable when a policy store backs it.
    # `mount_admin=False` keeps it OFF this app so a deployment can serve it
    # on a separate listener via `create_admin_app` (liminal#74) and restrict
    # that listener at the network layer.
    if policy_store is not None and mount_admin:
        app.include_router(build_admin_router())
    return app


def create_admin_app(
    *,
    jwt_verifier: JWTVerifier,
    policy_store: PolicyStore,
) -> FastAPI:
    """A FastAPI app carrying ONLY the federation admin surface (liminal#74).

    Pair with ``create_app(..., mount_admin=False)`` and bind this app to its
    own listener (``liminal serve --admin-port``): the data-plane port then
    carries no ``/admin/*`` routes at all, so a network policy can scope the
    admin listener to the governing service alone. Auth semantics are the
    same guardian gate the mounted router enforces -- a parent-issuer token
    whose persona holds a parent row with ``admin:*``."""
    app = FastAPI(title="liminal federation admin", version=__version__)
    app.state.jwt_verifier = jwt_verifier
    app.state.policy_store = policy_store
    app.include_router(build_admin_router())
    return app
