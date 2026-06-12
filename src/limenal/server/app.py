"""FastAPI app factory.

Wires the registry → dispatcher → MCP route. Auth is injectable so tests
can pass a StaticKeySetVerifier and production wires URLJWKSVerifier
against Cabal Core.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from limenal import __version__
from limenal.dispatch import InProcessDispatcher
from limenal.registry import Registry, discover_handlers
from limenal.server.auth import JWTVerifier
from limenal.server.routes import build_router

log = structlog.get_logger(__name__)


def create_app(
    *,
    jwt_verifier: JWTVerifier | None = None,
    registry: Registry | None = None,
    credential_resolver: Callable[[str, str], dict[str, str]] | None = None,
    server_name: str = "limenal",
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
    """

    # Resolve the registry once; lifespan closes over it.
    reg = registry if registry is not None else discover_handlers()
    dispatcher = InProcessDispatcher(registry=reg)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        log.info("limenal.startup", version=__version__, handlers=reg.names())
        # Call startup() on handlers that define it (e.g. to open pooled clients).
        handlers = [record.handler for record in reg]
        for handler in handlers:
            if hasattr(handler, "startup"):
                await handler.startup()
        yield
        # Call shutdown() in reverse order.
        for handler in reversed(handlers):
            if hasattr(handler, "shutdown"):
                await handler.shutdown()
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

    app.include_router(build_router())
    return app
