"""FastAPI app factory.

Wires the registry → dispatcher → MCP route. Auth is injectable so tests
can pass a StaticKeySetVerifier and production wires URLJWKSVerifier
against Cabal Core.

Trusted-network deployments (Claude Desktop talking to localhost, a
script wrapping limenal in a single-operator environment) can disable
JWT enforcement entirely by setting `LIMENAL_AUTH_DISABLED=1`. A loud
WARN banner fires at startup so the mode can't ship to prod by
accident; a JWT verifier supplied alongside the env var is a
configuration error and raises at create_app time.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI

from limenal import __version__
from limenal.dispatch import Multiplexer
from limenal.registry import Registry, discover_handlers
from limenal.server.admin import build_admin_router
from limenal.server.auth import JWTVerifier, MultiIssuerJWKSVerifier
from limenal.server.policy import PolicyStore
from limenal.server.routes import build_router
from limenal.target import (
    InProcessTarget,
    Target,
    TargetSpec,
    build_http_targets,
)

log = structlog.get_logger(__name__)


_AUTH_DISABLED_ENV = "LIMENAL_AUTH_DISABLED"
_AUTH_DISABLED_TRUTHY = {"1", "true", "yes", "on"}


def _auth_disabled_from_env() -> bool:
    """Returns True iff LIMENAL_AUTH_DISABLED is set to a truthy value."""
    return os.environ.get(_AUTH_DISABLED_ENV, "").lower() in _AUTH_DISABLED_TRUTHY


def create_app(
    *,
    jwt_verifier: JWTVerifier | None = None,
    registry: Registry | None = None,
    credential_resolver: Callable[[str, str], Awaitable[dict[str, str]]] | None = None,
    server_name: str = "limenal",
    targets: list[TargetSpec] | None = None,
    policy_store: PolicyStore | None = None,
    policy_scope_for: Callable[[str], str | None] | None = None,
    policy_tool_extras: dict[str, Any] | None = None,
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
        raise RuntimeError(
            f"limenal misconfiguration: {_AUTH_DISABLED_ENV}=1 is set but a "
            "JWT verifier was passed to create_app(). These are mutually "
            "exclusive — pick one. Set the env var only for trusted-network "
            "deployments (single operator, localhost client)."
        )

    # Sovereign safety invariant: a multi-issuer verifier trusts several cabals,
    # so it MUST NOT run on the token-embedded authz path — that would let any
    # federated cabal self-grant scope via its own scope/tool_extras claims.
    # A PolicyStore (server-side authorization) is required alongside it.
    if isinstance(jwt_verifier, MultiIssuerJWKSVerifier) and policy_store is None:
        raise RuntimeError(
            "limenal misconfiguration: a MultiIssuerJWKSVerifier requires a "
            "policy_store. Without server-side authorization, a federated cabal "
            "could self-grant scope through its own token claims. Wire a "
            "PolicyStore (e.g. SqlitePolicyStore) into create_app()."
        )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        log.info("limenal.startup", version=__version__, handlers=reg.names())
        if auth_disabled:
            # Loud banner so this can't ship to prod without someone seeing it.
            log.warning(
                "limenal.AUTH_DISABLED",
                msg=(
                    "JWT enforcement disabled via LIMENAL_AUTH_DISABLED. Every "
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
        log.info("limenal.shutdown")

    app = FastAPI(
        title="limenal MCP gateway",
        version=__version__,
        lifespan=lifespan,
    )

    app.state.registry = reg
    app.state.dispatcher = dispatcher
    app.state.jwt_verifier = jwt_verifier
    app.state.credential_resolver = credential_resolver
    app.state.server_name = server_name
    app.state.auth_disabled = auth_disabled
    app.state.policy_store = policy_store
    app.state.policy_scope_for = policy_scope_for
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
            "limenal.policy_store_inert",
            msg=(
                "a policy_store is wired but LIMENAL_AUTH_DISABLED=1 — sovereign "
                "authorization is bypassed (anonymous claims, no policy resolve)."
            ),
        )

    app.include_router(build_router())
    # Federation admin surface is only reachable when a policy store backs it.
    if policy_store is not None:
        app.include_router(build_admin_router())
    return app
