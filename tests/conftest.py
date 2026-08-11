"""Shared server fixtures."""

from __future__ import annotations

import time

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from liminal.handlers.scratchpad import ScratchpadHandler
from liminal.registry import Registry
from liminal.registry.discover import register_explicit
from liminal.server import StaticKeySetVerifier, create_app


@pytest.fixture(scope="session")
def signing_key() -> RSAKey:
    """A throwaway RSA keypair for signing test JWTs."""
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key = RSAKey.import_key(pem)
    key.ensure_kid()
    return key


@pytest.fixture(scope="session")
def keyset(signing_key) -> KeySet:
    return KeySet([signing_key])


@pytest.fixture
def mint_token(signing_key):
    def _mint(
        *,
        sub: str = "rook-primus",
        persona: str = "rook",
        iss: str = "cabal-core",
        ttl: int = 60,
    ) -> str:
        now = int(time.time())
        header = {"alg": "RS256", "kid": signing_key.kid, "typ": "JWT"}
        payload = {
            "iss": iss,
            "sub": sub,
            "aud": "liminal",
            "iat": now,
            "exp": now + ttl,
            "cabal_persona": persona,
            "cabal_scope": ["dispatch"],
        }
        return jwt.encode(header, payload, signing_key)

    return _mint


@pytest.fixture
def registry() -> Registry:
    """Fresh Registry per test so handlers don't leak in-memory state."""
    r = Registry()
    register_explicit(r, "scratchpad", ScratchpadHandler())
    return r


@pytest.fixture
def app(keyset, registry) -> FastAPI:
    verifier = StaticKeySetVerifier(key_set=keyset)
    return create_app(jwt_verifier=verifier, registry=registry)


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
