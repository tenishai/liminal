"""JWT bearer authentication for the MCP server.

A Verifier knows how to:
  1. find the right public key for a JWT (via its `kid` header), and
  2. validate signature + claims, returning the decoded payload.

Two built-ins:
  - StaticKeySetVerifier — KeySet wired at construction. Used by tests.
  - URLJWKSVerifier — fetches a remote JWKS URL with TTL caching.
                      Production wire-up against Cabal Core's
                      /.well-known/jwks.json.

The verifier extracts `cabal_persona` and `sub` claims into the persona-
identity tuple limenal needs to build a Context for the dispatcher. Any
JWT with a verifiable signature + recognized issuer is admitted; finer-
grained authorization (per-tool ACLs) is a Phase 2 concern.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
import structlog
from joserfc import jwt as jwt_lib
from joserfc.jwk import KeySet

log = structlog.get_logger(__name__)


DEFAULT_ISS = "cabal-core"
DEFAULT_LEEWAY_SECONDS = 30


class AuthError(RuntimeError):
    """JWT could not be verified."""


@dataclass(slots=True)
class VerifiedClaims:
    """What the dispatcher needs to build a Context.

    `raw` carries the full decoded payload so a handler that needs to peek
    at e.g. `aud` or custom claims can.
    """

    identity: str
    agent_name: str
    raw: dict[str, Any]


class JWTVerifier(Protocol):
    """Verifies a bearer token, returning the claims we route on."""

    def verify(self, token: str) -> VerifiedClaims:
        ...


# ---- Static KeySet (tests) ------------------------------------------------


@dataclass(slots=True)
class StaticKeySetVerifier:
    key_set: KeySet
    expected_issuer: str = DEFAULT_ISS
    leeway_seconds: int = DEFAULT_LEEWAY_SECONDS

    def verify(self, token: str) -> VerifiedClaims:
        return _verify_against_keyset(
            token,
            key_set=self.key_set,
            expected_issuer=self.expected_issuer,
            leeway_seconds=self.leeway_seconds,
        )


# ---- Remote JWKS (production) ---------------------------------------------


@dataclass
class URLJWKSVerifier:
    """Fetches a JWKS URL, caches with TTL, re-fetches on cache miss.

    The cache invalidates on a `kid` not found in the current set —
    triggers a re-fetch in case the upstream rotated keys recently. This
    is the same pattern Cabal's RefreshingJWKSProvider uses, adapted for
    the HTTP boundary instead of the in-process broadcast bus.
    """

    jwks_url: str
    expected_issuer: str = DEFAULT_ISS
    cache_ttl_seconds: float = 300.0
    leeway_seconds: int = DEFAULT_LEEWAY_SECONDS

    _client: httpx.Client | None = None
    _cached: KeySet | None = field(default=None, init=False)
    _cached_at: float = field(default=0.0, init=False)

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=httpx.Timeout(10.0))
        return self._client

    def _fetch(self) -> KeySet:
        log.info("auth.jwks.fetch", url=self.jwks_url)
        resp = self._http().get(self.jwks_url)
        resp.raise_for_status()
        body = resp.json()
        keys = body.get("keys", [])
        ks = KeySet.import_key_set({"keys": keys}) if keys else KeySet([])
        self._cached = ks
        self._cached_at = time.monotonic()
        return ks

    def _current(self) -> KeySet:
        now = time.monotonic()
        if self._cached is None or (now - self._cached_at) > self.cache_ttl_seconds:
            return self._fetch()
        return self._cached

    def verify(self, token: str) -> VerifiedClaims:
        # First attempt against cached set; if the kid is missing, force a
        # fresh fetch (key rotation just happened).
        try:
            return _verify_against_keyset(
                token,
                key_set=self._current(),
                expected_issuer=self.expected_issuer,
                leeway_seconds=self.leeway_seconds,
            )
        except AuthError as exc:
            if "kid" in str(exc).lower():
                # Force a re-fetch and try again
                self._cached = None
                return _verify_against_keyset(
                    token,
                    key_set=self._current(),
                    expected_issuer=self.expected_issuer,
                    leeway_seconds=self.leeway_seconds,
                )
            raise


# ---- shared verify helper -------------------------------------------------


def _verify_against_keyset(
    token: str,
    *,
    key_set: KeySet,
    expected_issuer: str,
    leeway_seconds: int,
) -> VerifiedClaims:
    try:
        decoded = jwt_lib.decode(token, key_set)
    except Exception as exc:  # noqa: BLE001
        raise AuthError(f"signature verification failed: {exc}") from exc

    claims = dict(decoded.claims)
    now = int(time.time())
    if claims.get("iss") != expected_issuer:
        raise AuthError(f"unexpected iss: {claims.get('iss')!r}")
    exp = claims.get("exp")
    if exp is None or now > int(exp) + leeway_seconds:
        raise AuthError("token expired")
    iat = claims.get("iat")
    if iat is None or int(iat) > now + leeway_seconds:
        raise AuthError("token issued in the future")

    persona = claims.get("cabal_persona") or claims.get("persona")
    sub = claims.get("sub")
    if not persona or not sub:
        raise AuthError(
            "token missing cabal_persona / sub claims (need both to dispatch)"
        )
    return VerifiedClaims(identity=str(persona), agent_name=str(sub), raw=claims)
