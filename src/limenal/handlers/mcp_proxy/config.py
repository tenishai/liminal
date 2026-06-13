"""Configuration shape for the MCP proxy handler.

Each ProxyConfig represents one upstream MCP server. Multiple proxies
can register against the same limenal instance — they're independent
and each gets its own namespace.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

AuthMethod = Literal["bearer", "service-token", "none"]


@dataclass(slots=True)
class ProxyConfig:
    """One upstream MCP server.

    Attributes:
        prefix: The handler name in limenal's registry. Becomes the
            namespace for the upstream's tools — a proxy with
            ``prefix="jira"`` and upstream tool ``"search"`` appears in
            the agent's tool list as ``"jira.search"``. Must not
            collide with any other registered handler.
        upstream_url: The upstream MCP server endpoint (HTTP/JSON-RPC).
        auth_method: How to authenticate to the upstream.

            ``"bearer"`` — static token in ``bearer_token``; sent as
                ``Authorization: Bearer <token>`` on every call.
            ``"service-token"`` — token resolved from
                ``ctx.credentials[credential_key]`` per-call, so it
                composes with limenal's existing credential resolver
                (which can fetch from cabal secrets or any backend).
            ``"none"`` — no Authorization header. Use for trusted-
                network upstreams or upstreams that auth via other
                means (mTLS, query param, etc.).

        bearer_token: Used when ``auth_method == "bearer"``. Required
            in that case.
        credential_key: Used when ``auth_method == "service-token"``.
            The key looked up in ``ctx.credentials``. Required in that
            case.
        timeout_seconds: Per-call timeout for forwarded requests.
        refresh_tools_interval_seconds: How often the background task
            re-fetches the upstream's tool list. 0 disables periodic
            refresh (tools are still fetched once at startup).
        relevance_signals: Free-form strings advertised in the
            capability card so the future semantic-routing layer
            knows when to surface this proxy's tools.
    """

    prefix: str
    upstream_url: str
    auth_method: AuthMethod = "none"
    bearer_token: str | None = None
    credential_key: str | None = None
    timeout_seconds: float = 30.0
    refresh_tools_interval_seconds: int = 300
    relevance_signals: tuple[str, ...] = ()
    client_name: str = "limenal-proxy"

    def validate(self) -> None:
        """Raise ValueError on invalid combinations."""
        if not self.prefix or "." in self.prefix:
            raise ValueError(
                f"proxy prefix {self.prefix!r} must be non-empty and "
                "contain no '.' (it becomes the handler name)"
            )
        if not self.upstream_url:
            raise ValueError("proxy upstream_url is required")
        if self.auth_method == "bearer" and not self.bearer_token:
            raise ValueError("auth_method='bearer' requires bearer_token")
        if self.auth_method == "service-token" and not self.credential_key:
            raise ValueError(
                "auth_method='service-token' requires credential_key"
            )
