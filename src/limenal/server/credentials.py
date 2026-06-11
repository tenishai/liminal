"""Credential resolution for handlers that need secrets.

Per design.md §"Credential Flow", credentials live in Cabal Core's
encrypted store and are fetched at handler-dispatch time:

    in solo mode that's a direct function call into Cabal Core's
    secrets module; in scale mode it's an authenticated HTTPS call to
    GET /secrets/<identity>/<handler> on Cabal Core. Cabal Core
    decrypts at request time and returns the dict.

This module provides the scale-mode adapter: `CabalCoreCredentialResolver`
calls Cabal Core's `/admin/secrets/{persona}/{handler}` HTTPS endpoint
with a bearer token, caches the result per `(persona, handler)` with a
TTL (15 minutes per the design doc), and re-fetches when stale or on
explicit invalidation.

Wire it via `create_app(credential_resolver=resolver.fetch)`. The
resolver hands an async callable to the route; the route awaits it.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import httpx
import structlog

log = structlog.get_logger(__name__)


DEFAULT_CACHE_TTL_SECONDS = 15 * 60  # 15 minutes per design.md


# The signature `create_app` expects for credential_resolver. Awaitable
# returning a dict[str, str] per (identity, handler).
CredentialResolver = Callable[[str, str], Awaitable[dict[str, str]]]


@dataclass
class CabalCoreCredentialResolver:
    """Fetches `(persona, handler)` credentials from Cabal Core.

    Args:
        cabal_url: base URL of the Cabal Core daemon (no trailing slash).
        token_provider: no-arg async callable returning the bearer token
            limenal presents to Cabal. The token's `cabal_scope` should
            include either `operator` or `secrets-fetch`.
        http_client: optional pre-built httpx.AsyncClient (tests pass
            an ASGITransport-backed client; production lets the resolver
            build its own).
        cache_ttl_seconds: per-(persona, handler) TTL. 15-minute default.
    """

    cabal_url: str
    token_provider: Callable[[], str]
    http_client: httpx.AsyncClient | None = None
    cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS

    _cache: dict[tuple[str, str], tuple[dict[str, str], float]] = field(
        default_factory=dict, init=False
    )

    def _http(self) -> httpx.AsyncClient:
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(timeout=httpx.Timeout(15.0))
        return self.http_client

    async def fetch(self, persona: str, handler: str) -> dict[str, str]:
        """The function `create_app(credential_resolver=...)` invokes.

        Network failures + auth errors do NOT raise — they log and
        return an empty dict so a temporarily-unreachable Cabal Core
        doesn't black-hole every credentialed tool call. The handler
        decides what to do with empty creds (typically: refuse with a
        structured error the agent can act on)."""
        cached = self._cache.get((persona, handler))
        now = time.monotonic()
        if cached is not None:
            creds, expires_at = cached
            if expires_at > now:
                return creds
            # expired — fall through to re-fetch
            del self._cache[(persona, handler)]

        url = f"{self.cabal_url.rstrip('/')}/admin/secrets/{persona}/{handler}"
        token = self.token_provider()
        try:
            resp = await self._http().get(
                url, headers={"Authorization": f"Bearer {token}"}
            )
        except httpx.HTTPError as exc:
            log.warning(
                "credentials.fetch_failed",
                persona=persona,
                handler=handler,
                error=str(exc),
            )
            return {}

        if resp.status_code != 200:
            log.warning(
                "credentials.fetch_non_200",
                persona=persona,
                handler=handler,
                status=resp.status_code,
                body=resp.text[:200],
            )
            return {}

        try:
            body = resp.json()
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "credentials.fetch_non_json",
                persona=persona,
                handler=handler,
                error=str(exc),
            )
            return {}

        creds = body.get("credentials") or {}
        if not isinstance(creds, dict):
            log.warning(
                "credentials.fetch_wrong_shape",
                persona=persona,
                handler=handler,
            )
            return {}

        # Coerce to str→str for the handler contract.
        coerced = {str(k): str(v) for k, v in creds.items()}
        self._cache[(persona, handler)] = (
            coerced,
            now + self.cache_ttl_seconds,
        )
        return coerced

    def invalidate(self, persona: str, handler: str) -> None:
        """Explicit cache-bust for one (persona, handler). Useful when
        Cabal Core notifies a rotation event."""
        self._cache.pop((persona, handler), None)

    def invalidate_all(self) -> None:
        self._cache.clear()

    def cache_size(self) -> int:
        return len(self._cache)

    async def aclose(self) -> None:
        if self.http_client is not None:
            await self.http_client.aclose()
