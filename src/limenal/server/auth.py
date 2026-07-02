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

import asyncio
import base64
import binascii
import json
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
import structlog
from joserfc import jwt as jwt_lib
from joserfc.jwk import KeySet

log = structlog.get_logger(__name__)


DEFAULT_ISS = "cabal-core"
DEFAULT_AUD = "limenal"
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
    # Which trusted issuer minted this token. Populated by the verify helper.
    # "" for legacy single-issuer callers and the auth-disabled anonymous path.
    # Sovereign (multi-issuer) authorization keys on it: (issuer, persona).
    issuer: str = ""


class JWTVerifier(Protocol):
    """Verifies a bearer token, returning the claims we route on."""

    async def verify(self, token: str) -> VerifiedClaims:
        ...


# ---- Static KeySet (tests) ------------------------------------------------


@dataclass(slots=True)
class StaticKeySetVerifier:
    key_set: KeySet
    expected_issuer: str = DEFAULT_ISS
    expected_audience: str | None = DEFAULT_AUD
    leeway_seconds: int = DEFAULT_LEEWAY_SECONDS

    async def verify(self, token: str) -> VerifiedClaims:
        return _verify_against_keyset(
            token,
            key_set=self.key_set,
            expected_issuer=self.expected_issuer,
            expected_audience=self.expected_audience,
            leeway_seconds=self.leeway_seconds,
        )


# ---- Remote JWKS (production) ---------------------------------------------


@dataclass
class URLJWKSVerifier:
    """Fetches a JWKS URL, caches with TTL, re-fetches on cache miss.

    The cache invalidates on a `kid` not found in the current set —
    triggers a re-fetch in case the upstream rotated keys recently. Uses
    AsyncClient so JWKS fetches never block the event loop.
    """

    jwks_url: str
    expected_issuer: str = DEFAULT_ISS
    cache_ttl_seconds: float = 300.0
    leeway_seconds: int = DEFAULT_LEEWAY_SECONDS
    expected_audience: str | None = DEFAULT_AUD
    # Minimum seconds between forced (kid-miss) re-fetches. Bounds the
    # amplification vector where a caller — who under multi-issuer can select
    # this verifier via an unverified `iss` — spams unknown-`kid` tokens to
    # drive cache-busting outbound JWKS fetches. A real key rotation is still
    # picked up on the first kid-miss; only the *rate* is capped.
    refetch_min_interval_seconds: float = 10.0

    _cached: KeySet | None = field(default=None, init=False)
    _cached_at: float = field(default=0.0, init=False)
    _last_refetch_at: float = field(default=0.0, init=False)
    _lock: asyncio.Lock | None = field(default=None, init=False)
    # Injectable AsyncClient for tests; production creates per-fetch clients.
    _client: httpx.AsyncClient | None = field(default=None, init=False)

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def _fetch(self) -> KeySet:
        log.info("auth.jwks.fetch", url=self.jwks_url)
        # Fail closed: a JWKS endpoint outage becomes an AuthError (→ 401 at
        # the route) rather than an httpx.HTTPStatusError that would surface
        # as a 500 (routes._authenticate only catches AuthError).
        try:
            if self._client is not None:
                resp = await self._client.get(self.jwks_url)
            else:
                async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
                    resp = await client.get(self.jwks_url)
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise AuthError(f"jwks fetch failed for {self.jwks_url}: {exc}") from exc
        keys = body.get("keys", [])
        ks = KeySet.import_key_set({"keys": keys}) if keys else KeySet([])
        self._cached = ks
        self._cached_at = time.monotonic()
        return ks

    async def _current(self) -> KeySet:
        now = time.monotonic()
        if self._cached is not None and (now - self._cached_at) <= self.cache_ttl_seconds:
            return self._cached
        async with self._get_lock():
            # Double-check after acquiring lock — another coroutine may have fetched.
            now = time.monotonic()
            if self._cached is None or (now - self._cached_at) > self.cache_ttl_seconds:
                return await self._fetch()
            return self._cached

    async def verify(self, token: str) -> VerifiedClaims:
        # First attempt against cached set; if the kid is missing, force a
        # fresh fetch (key rotation just happened).
        try:
            return _verify_against_keyset(
                token,
                key_set=await self._current(),
                expected_issuer=self.expected_issuer,
                expected_audience=self.expected_audience,
                leeway_seconds=self.leeway_seconds,
            )
        except AuthError as exc:
            if "kid" in str(exc).lower() and self._may_refetch():
                # Force a re-fetch and try again (throttled — see _may_refetch).
                async with self._get_lock():
                    self._cached = None
                return _verify_against_keyset(
                    token,
                    key_set=await self._current(),
                    expected_issuer=self.expected_issuer,
                    expected_audience=self.expected_audience,
                    leeway_seconds=self.leeway_seconds,
                )
            raise

    def _may_refetch(self) -> bool:
        """Rate-limit forced (kid-miss) re-fetches to bound the amplification
        vector. Returns True at most once per `refetch_min_interval_seconds`.
        A real rotation lands on the first kid-miss; a flood of unknown kids
        can trigger at most one outbound fetch per interval."""
        now = time.monotonic()
        if now - self._last_refetch_at < self.refetch_min_interval_seconds:
            return False
        self._last_refetch_at = now
        return True


# ---- shared verify helper -------------------------------------------------


def _aud_ok(aud: Any, expected: str | None) -> bool:
    """Audience match that accepts a list-valued `aud`.

    RFC 7519 permits `aud` to be a string OR an array of strings. Cabal mints
    per-target tokens (cabal D-010) whose `aud` may carry several audiences,
    so exact string equality is wrong. `None` expected means "don't check".
    """
    if expected is None:
        return True
    if isinstance(aud, str):
        return aud == expected
    if isinstance(aud, (list, tuple)):
        return expected in aud
    return False


def _verify_against_keyset(
    token: str,
    *,
    key_set: KeySet,
    expected_issuer: str,
    expected_audience: str | None,
    leeway_seconds: int,
) -> VerifiedClaims:
    try:
        decoded = jwt_lib.decode(token, key_set)
    except Exception as exc:  # noqa: BLE001
        raise AuthError(f"signature verification failed: {exc}") from exc

    # Algorithm pin — defense in depth against algorithm-confusion attacks.
    alg = (decoded.header or {}).get("alg")
    if alg != "RS256":
        raise AuthError(f"algorithm {alg!r} not accepted (expected RS256)")

    claims = dict(decoded.claims)
    now = int(time.time())
    if claims.get("iss") != expected_issuer:
        raise AuthError(f"unexpected iss: {claims.get('iss')!r}")

    if not _aud_ok(claims.get("aud"), expected_audience):
        raise AuthError("invalid_audience")

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
    return VerifiedClaims(
        identity=str(persona),
        agent_name=str(sub),
        raw=claims,
        issuer=str(claims.get("iss")),
    )


# ---- Multi-issuer (sovereign / federated) ---------------------------------


def _peek_iss(token: str) -> str | None:
    """Read the UNVERIFIED `iss` claim to select which issuer's keys to use.

    Selection only — this value is never trusted. Signature verification
    against the selected issuer's KeySet (in the delegated verify) is the
    real gate: a token that lies about `iss` to pick issuer X's keys will
    fail X's signature check and be rejected. Safe by construction.
    """
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        payload = json.loads(base64.urlsafe_b64decode(seg))
    except (IndexError, ValueError, binascii.Error, json.JSONDecodeError):
        return None
    iss = payload.get("iss")
    return iss if isinstance(iss, str) else None


@dataclass
class MultiIssuerJWKSVerifier:
    """Verifies tokens minted by any of several trusted cabals.

    Each issuer id maps to its own single-issuer verifier (production wires a
    per-issuer `URLJWKSVerifier`, so every issuer keeps an independent JWKS
    cache + kid-miss re-fetch and one issuer's JWKS outage only denies that
    issuer's callers). Tests inject `StaticKeySetVerifier`s.

    `parents` carries the issuers with guardian standing — used by the admin
    plane to reject `admin/*` from non-parent issuers before touching policy.
    """

    registry: dict[str, JWTVerifier]
    parents: frozenset[str] = frozenset()

    async def verify(self, token: str) -> VerifiedClaims:
        iss = _peek_iss(token)
        if iss is None:
            raise AuthError("token missing iss claim")
        inner = self.registry.get(iss)
        if inner is None:
            raise AuthError(f"untrusted issuer: {iss!r}")
        # Delegate: signature vs that issuer's keys, RS256 pin, iss/aud/exp/iat,
        # persona+sub. The inner verifier's expected_issuer == iss re-confirms
        # the peeked value; VerifiedClaims.issuer comes back set.
        return await inner.verify(token)


@dataclass(frozen=True, slots=True)
class IssuerConfig:
    """One trusted cabal in a sovereign service's trust registry."""

    id: str
    jwks_uri: str
    parent: bool = False


def build_multi_issuer_verifier(
    issuers: list[IssuerConfig],
    *,
    service_audience: str,
    cache_ttl_seconds: float = 300.0,
) -> MultiIssuerJWKSVerifier:
    """Wire a `MultiIssuerJWKSVerifier` from trust-registry config.

    `service_audience` is this sovereign persona's stable service id, which
    every caller must mint into the token `aud`. Exactly one issuer must be
    flagged `parent` — the guardian that graduated this persona.
    """
    if not issuers:
        raise ValueError("trust registry is empty; at least one issuer required")
    ids = [i.id for i in issuers]
    if len(set(ids)) != len(ids):
        raise ValueError(f"duplicate issuer ids in trust registry: {ids}")
    parents = frozenset(i.id for i in issuers if i.parent)
    if len(parents) != 1:
        raise ValueError(
            f"exactly one parent issuer required, got {len(parents)}: {sorted(parents)}"
        )
    registry: dict[str, JWTVerifier] = {
        i.id: URLJWKSVerifier(
            jwks_url=i.jwks_uri,
            expected_issuer=i.id,
            expected_audience=service_audience,
            cache_ttl_seconds=cache_ttl_seconds,
        )
        for i in issuers
    }
    return MultiIssuerJWKSVerifier(registry=registry, parents=parents)
