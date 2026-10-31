"""Catalog token providers: a bearer for the catalog fetch, minted on demand.

Some upstreams refuse an unauthenticated ``initialize`` (GitHub's hosted MCP
server) while every persona call carries that persona's own leased credential.
The catalog fetch, which no persona makes, then needs a credential of its own.
``catalog_headers_env`` covers upstreams that take it in a named header; an
upstream that wants it on ``Authorization`` cannot take a static value there,
because liminal owns that header and a long-lived bearer in an env var is a
secret someone has to rotate.

A provider is the alternative: a deployment registers an async callable under
the ``liminal.catalog_tokens`` entry-point group, a target names it with
``catalog_token_provider``, and ``HttpTarget`` awaits it before every catalog
fetch (startup and each refresh). The callable returns the bearer value, which
the catalog client encodes with the target's ``auth_scheme``. The provider owns
how the token is made (a GitHub App installation token, a cloud identity
token, ...) and liminal never sees a long-lived secret.

Resolution FAILS CLOSED, unlike handler discovery: a target that names a
provider liminal cannot load must not start, since starting it would mean an
unauthenticated catalog fetch the upstream refuses, or worse, a silently empty
tool list.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from importlib.metadata import entry_points

ENTRY_POINT_GROUP = "liminal.catalog_tokens"

CatalogTokenProvider = Callable[[], Awaitable[str]]


class CatalogTokenProviderError(RuntimeError):
    """A named provider could not be loaded. Raised at target startup."""


def load_catalog_token_provider(name: str) -> CatalogTokenProvider:
    """Load the provider registered as ``name``.

    The entry point names a factory; calling it with no arguments returns the
    provider, an async callable taking no arguments and returning the token.
    Unknown names, import errors and factory errors all raise
    ``CatalogTokenProviderError`` naming the provider, so the target that
    asked for it fails its startup with the cause in the log."""
    try:
        eps = {ep.name: ep for ep in entry_points(group=ENTRY_POINT_GROUP)}
    except Exception as exc:  # noqa: BLE001
        raise CatalogTokenProviderError(
            f"catalog token provider {name!r}: entry-point group "
            f"{ENTRY_POINT_GROUP!r} unreadable: {exc}"
        ) from exc
    ep = eps.get(name)
    if ep is None:
        known = ", ".join(sorted(eps)) or "none registered"
        raise CatalogTokenProviderError(
            f"catalog token provider {name!r} is not registered under "
            f"{ENTRY_POINT_GROUP!r} (known: {known})"
        )
    try:
        factory = ep.load()
        provider = factory()
    except Exception as exc:  # noqa: BLE001
        raise CatalogTokenProviderError(
            f"catalog token provider {name!r} failed to load: {exc}"
        ) from exc
    if not callable(provider):
        raise CatalogTokenProviderError(
            f"catalog token provider {name!r} must be an async callable, "
            f"got {type(provider).__name__!r}"
        )
    return provider
