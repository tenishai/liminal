"""Browser-request guard for POST /mcp (liminal#190).

A web page in the operator's browser can POST to a loopback liminal: a
``text/plain`` (or untyped Blob) body is a CORS "simple" request, so no
preflight runs, and DNS rebinding makes an attacker's page same-origin. Under
``LIMINAL_AUTH_DISABLED=1`` that reaches every tool. The MCP Streamable HTTP
transport says servers MUST validate ``Origin`` for this reason.

Two checks, both before the body is read:

- ``Origin``: absent is allowed (non-browser clients don't send it). Present,
  it must be a loopback origin (``localhost``, ``127.0.0.1``, ``[::1]``, any
  port, http or https) or listed in ``LIMINAL_ALLOWED_ORIGINS``. ``null`` is
  refused: sandboxed iframes and ``file:`` pages send it, so it is attacker-
  reachable.
- ``Content-Type``: the media type must be ``application/json``. That is never
  a simple request, so a cross-origin page cannot send it without a preflight,
  which liminal does not answer.

Residual: a page served from another loopback origin passes the Origin check.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

import structlog

log = structlog.get_logger(__name__)

_ALLOWED_ORIGINS_ENV = "LIMINAL_ALLOWED_ORIGINS"
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def allowed_origins_from_env() -> frozenset[str]:
    """Extra allowed origins, comma-separated, compared exactly after
    lowercasing and dropping a trailing slash (``https://ui.example:8443``)."""
    raw = os.environ.get(_ALLOWED_ORIGINS_ENV, "")
    return frozenset(
        o.strip().lower().rstrip("/") for o in raw.split(",") if o.strip()
    )


def _is_loopback_origin(origin: str) -> bool:
    try:
        parts = urlsplit(origin)
        host = parts.hostname
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and host in _LOOPBACK_HOSTS


def origin_refusal(origin: str | None, extra: frozenset[str]) -> str | None:
    """None if the Origin header is acceptable, else the refusal reason."""
    if origin is None:
        return None
    norm = origin.strip().lower().rstrip("/")
    if norm in extra or _is_loopback_origin(norm):
        return None
    log.debug("request_guard.origin_refused", origin=origin)
    return "origin not allowed"


def content_type_refusal(content_type: str | None) -> str | None:
    """None if the media type is application/json, else the refusal reason."""
    media = (content_type or "").split(";", 1)[0].strip().lower()
    if media == "application/json":
        return None
    log.debug("request_guard.content_type_refused", content_type=content_type)
    return "Content-Type must be application/json"
