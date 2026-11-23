"""Cabal's subject revocation list, cached in memory (liminal#228).

`POST /admin/token/revoke {"sub": ...}` at cabal stops that subject at cabal at
once. Without this module liminal kept accepting the subject's tokens on every
tool that never calls cabal until each token's `exp`. `RevocationList` fetches
`GET {cabal_url}/auth/revocations` with the same bearer token the credential
resolver presents and answers `is_revoked(sub, iat)`: a token whose `iat` is
before its subject's `not_before` cutoff is revoked.

The list is refreshed at most once per `ttl_seconds` (30 by default), and only
when a request needs it. One request awaits the refresh; requests that arrive
while it runs use the list on hand. A failed attempt also waits out the TTL
before the next, so a cabal that is down is asked once per window, not once per
request.

Failure posture is fail-soft, like `CabalCoreCredentialResolver` (design.md
"Failure posture"):

- never fetched (cabal unreachable, a non-200 such as an older cabal's 404, or a
  malformed body): tokens are accepted as before, with one warning;
- a refresh fails after a good fetch: the last good list stays in force, and the
  failure is logged.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
import structlog

log = structlog.get_logger(__name__)


DEFAULT_REVOCATION_TTL_SECONDS = 30.0
REVOCATIONS_PATH = "/auth/revocations"


@dataclass
class RevocationList:
    """One cabal's revocation list.

    Args:
        cabal_url: base URL of the cabal (the `--cabal-url` liminal fetches
            secrets from).
        issuer: the `iss` that cabal mints. Only tokens from this issuer are
            checked against this list.
        token_provider: no-arg callable returning the bearer token (the same
            one `CabalCoreCredentialResolver` uses). Never logged.
        http_client: optional pre-built AsyncClient (tests).
        ttl_seconds: how long a fetched list, or a failed attempt, stands
            before the next fetch.
        clock: monotonic clock, injectable for tests.
    """

    cabal_url: str
    issuer: str
    token_provider: Callable[[], str]
    http_client: httpx.AsyncClient | None = None
    ttl_seconds: float = DEFAULT_REVOCATION_TTL_SECONDS
    clock: Callable[[], float] = time.monotonic

    # sub -> not_before (epoch seconds). None until the first good fetch.
    _revocations: dict[str, float] | None = field(default=None, init=False)
    # Monotonic time of the last attempt, good or failed. None: never tried.
    _attempted_at: float | None = field(default=None, init=False)
    _warned_unfetched: bool = field(default=False, init=False)
    _lock: asyncio.Lock | None = field(default=None, init=False)

    @property
    def url(self) -> str:
        return f"{self.cabal_url.rstrip('/')}{REVOCATIONS_PATH}"

    def _http(self) -> httpx.AsyncClient:
        if self.http_client is None:
            # Same timeout as CabalCoreCredentialResolver.
            self.http_client = httpx.AsyncClient(timeout=httpx.Timeout(15.0))
        return self.http_client

    def _stale(self) -> bool:
        return (
            self._attempted_at is None
            or self.clock() - self._attempted_at >= self.ttl_seconds
        )

    async def _maybe_refresh(self) -> None:
        if not self._stale():
            return
        if self._lock is None:
            self._lock = asyncio.Lock()
        if self._lock.locked():
            # A refresh is in flight; use the list on hand rather than queue.
            return
        async with self._lock:
            if self._stale():
                await self._refresh()

    async def _refresh(self) -> None:
        self._attempted_at = self.clock()
        log.debug("auth.revocations.fetch", url=self.url)
        failure: dict[str, object] | None = None
        revocations: dict[str, float] | None = None
        try:
            resp = await self._http().get(
                self.url,
                headers={"Authorization": f"Bearer {self.token_provider()}"},
            )
        except httpx.HTTPError as exc:
            failure = {"error": type(exc).__name__}
        else:
            if resp.status_code != 200:
                failure = {"status": resp.status_code}
            else:
                revocations = _parse(resp)
                if revocations is None:
                    failure = {"error": "malformed body"}
        if revocations is not None:
            self._revocations = revocations
            log.debug("auth.revocations.ok", url=self.url, subjects=len(revocations))
            return
        if self._revocations is not None:
            log.warning(
                "auth.revocations.refresh_failed_keeping_last",
                url=self.url,
                subjects=len(self._revocations),
                **failure,
            )
        elif not self._warned_unfetched:
            self._warned_unfetched = True
            log.warning(
                "auth.revocations.unavailable",
                url=self.url,
                msg=(
                    "cabal's revocation list could not be fetched (an older cabal "
                    "answers 404); tokens are accepted without a revocation check "
                    "until a fetch succeeds"
                ),
                **failure,
            )
        else:
            log.debug("auth.revocations.still_unavailable", url=self.url, **failure)

    async def is_revoked(self, sub: str, iat: float) -> bool:
        """True iff cabal revoked `sub` with a cutoff after `iat`."""
        await self._maybe_refresh()
        if self._revocations is None:
            return False
        not_before = self._revocations.get(sub)
        return not_before is not None and iat < not_before

    async def aclose(self) -> None:
        if self.http_client is not None:
            await self.http_client.aclose()


def _parse(resp: httpx.Response) -> dict[str, float] | None:
    """`{"revocations": {sub: not_before, ...}, ...}` or None if malformed."""
    try:
        body = resp.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    raw = body.get("revocations")
    if not isinstance(raw, dict):
        return None
    out: dict[str, float] = {}
    for sub, not_before in raw.items():
        if isinstance(not_before, bool) or not isinstance(not_before, (int, float)):
            return None
        out[str(sub)] = float(not_before)
    return out
