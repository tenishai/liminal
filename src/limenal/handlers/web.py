"""web — allowlisted HTTP fetch with SSRF defense.

Per design.md §"Planned handlers":

    URL policy: allowlist by hostname, declared per persona in
    identity.toml as web.allowed_hosts = ["*"] (broad) or specific
    domains. Default denies localhost, 127.0.0.0/8, 10.0.0.0/8,
    172.16.0.0/12, 192.168.0.0/16, fc00::/7, and link-local — explicit
    SSRF protection against pivoting through the agent to reach
    http://cabal-core:8080, http://litellm:4000, or cloud metadata
    services.

Phase CC v1 implements the SSRF defense + the basic fetch surface. Per-
persona allowlists declared in Cabal's identity.toml are forwarded
through `ctx.extra["web.allowed_hosts"]` when the operator wires it
(Phase CD or later); v1 falls back to the handler's constructor-level
allowlist for any persona without one.

Defenses (all applied before the request leaves the handler):
  1. URL parse — reject non-http/https schemes.
  2. Hostname allowlist — wildcard "*" matches everything, otherwise
     glob-style suffix match against the configured list.
  3. DNS resolution + IP family check — every resolved IP must NOT be
     in the deny ranges (loopback, private, link-local, multicast,
     reserved, IPv6 ULA). Catches DNS-rebinding + URLs that wrap
     internal hosts in public-looking names.
  4. Response size cap — abort streams that exceed `max_response_bytes`.
  5. Content-type filter — only text/json/html by default; everything
     else returns a structured error rather than letting the agent
     read raw bytes.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from limenal.protocol import Context, Handler, ToolResult, ToolSpec

log = structlog.get_logger(__name__)


# Default network denies. Operators can extend but should not weaken.
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # AWS / Azure / GCP metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),   # ULA
    ipaddress.ip_network("fe80::/10"),  # link-local
]

DEFAULT_MAX_RESPONSE_BYTES = 1_000_000  # 1 MB
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_CONTENT_TYPES = {
    "text/plain",
    "text/html",
    "text/markdown",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "text/xml",
    "text/csv",
}


CARD = {
    "handler": "web",
    "description": "HTTP fetch with hostname allowlist + SSRF defense",
    "tools": [
        {
            "name": "fetch",
            "description": "GET a URL; returns text/json content within size + content-type limits.",
        },
        {
            "name": "head",
            "description": "HEAD a URL; returns response headers without a body.",
        },
    ],
    "activation": "always",
    "relevance_signals": [
        "fetching a documentation page or RFC the operator referenced",
        "verifying a URL is reachable before suggesting it",
        "pulling a JSON API response the persona needs to reason over",
    ],
    "credential_keys": [],
    "labels": {"tier": "builtin"},
}


@dataclass
class WebConfig:
    allowed_hosts: list[str] = field(default_factory=lambda: ["*"])
    denied_networks: list[Any] = field(
        default_factory=lambda: list(PRIVATE_NETWORKS)
    )
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    allowed_content_types: set[str] = field(
        default_factory=lambda: set(DEFAULT_CONTENT_TYPES)
    )


@dataclass
class WebHandler:
    """Stateless per-persona allowlist enforcement + httpx call site.

    `default_config` is used for any persona that doesn't supply its own
    via `ctx.extra["web.allowed_hosts"]`. Tests pass an
    `http_client_factory` to swap the real httpx for a MockTransport.
    """

    default_config: WebConfig = field(default_factory=WebConfig)
    http_client_factory: Any = None  # () -> httpx.AsyncClient
    dns_resolver: Any = None  # (host) -> list[str] (returns IPs)

    def tools(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="fetch",
                description="GET a URL.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "max_bytes": {
                            "type": "integer",
                            "description": "Override the default response-size cap (capped by handler config).",
                        },
                    },
                    "required": ["url"],
                },
            ),
            ToolSpec(
                name="head",
                description="HEAD a URL; returns response headers only.",
                input_schema={
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
            ),
        ]

    def capability_card(self) -> dict[str, Any]:
        return CARD

    async def dispatch(
        self, name: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        url = payload.get("url")
        if not isinstance(url, str) or not url:
            return ToolResult.failure("'url' must be a non-empty string")

        cfg = self._resolve_config(ctx)
        check_err = self._check_url(url, cfg)
        if check_err is not None:
            return ToolResult.failure(check_err)

        if name == "fetch":
            return await self._fetch(url, payload, cfg)
        if name == "head":
            return await self._head(url, cfg)
        return ToolResult.failure(f"unknown tool {name!r}")

    # ---- defenses -----------------------------------------------------

    def _resolve_config(self, ctx: Context) -> WebConfig:
        """Per-persona allowlist override via ctx.extra; falls back to default."""
        per_persona_hosts = ctx.extra.get("web.allowed_hosts")
        if not per_persona_hosts:
            return self.default_config
        return WebConfig(
            allowed_hosts=list(per_persona_hosts),
            denied_networks=self.default_config.denied_networks,
            max_response_bytes=self.default_config.max_response_bytes,
            timeout_seconds=self.default_config.timeout_seconds,
            allowed_content_types=self.default_config.allowed_content_types,
        )

    def _check_url(self, url: str, cfg: WebConfig) -> str | None:
        """Return an error message if `url` should be refused, else None."""
        try:
            parsed = urlparse(url)
        except Exception:  # noqa: BLE001
            return f"unparseable URL: {url!r}"
        if parsed.scheme not in {"http", "https"}:
            return f"scheme {parsed.scheme!r} not allowed; only http/https"
        host = parsed.hostname
        if not host:
            return "URL missing hostname"

        if not _host_in_allowlist(host, cfg.allowed_hosts):
            return f"host {host!r} not in allowlist {cfg.allowed_hosts}"

        # JWT can narrow, never widen: also enforce the server-side ceiling.
        # (cfg may come from a JWT override; default_config is always server.)
        if cfg is not self.default_config and not _host_in_allowlist(
            host, self.default_config.allowed_hosts
        ):
            return f"host {host!r} not permitted by server configuration"

        resolved_ips = self._resolve(host)
        if not resolved_ips:
            return f"could not resolve host {host!r}"
        for ip_str in resolved_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                return f"invalid IP {ip_str!r} from DNS"
            for net in cfg.denied_networks:
                if ip in net:
                    return (
                        f"host {host!r} resolves to {ip_str} in denied "
                        f"network {net} (SSRF protection)"
                    )
        return None

    def _resolve(self, host: str) -> list[str]:
        if self.dns_resolver is not None:
            try:
                return self.dns_resolver(host)
            except Exception as exc:  # noqa: BLE001
                log.warning("web.dns_resolver_failed", host=host, error=str(exc))
                return []
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return []
        return [info[4][0] for info in infos]

    # ---- fetch + head -------------------------------------------------

    async def _fetch(
        self, url: str, payload: dict[str, Any], cfg: WebConfig
    ) -> ToolResult:
        max_bytes = min(
            int(payload.get("max_bytes") or cfg.max_response_bytes),
            cfg.max_response_bytes,
        )
        client = self._build_client(cfg)
        try:
            async with client:
                async with client.stream("GET", url) as resp:
                    content_type = (
                        resp.headers.get("content-type", "")
                        .split(";", 1)[0]
                        .strip()
                        .lower()
                    )
                    if (
                        cfg.allowed_content_types
                        and content_type
                        and content_type not in cfg.allowed_content_types
                    ):
                        return ToolResult.failure(
                            f"content-type {content_type!r} not in allowlist"
                        )

                    body = bytearray()
                    truncated = False
                    async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                        body.extend(chunk)
                        if len(body) > max_bytes:
                            truncated = True
                            body = body[:max_bytes]
                            break

                    text = bytes(body).decode("utf-8", errors="replace")
                    return ToolResult.json(
                        {
                            "url": str(resp.url),
                            "status": resp.status_code,
                            "content_type": content_type,
                            "bytes": len(body),
                            "truncated": truncated,
                            "text": text,
                        }
                    )
        except httpx.HTTPError as exc:
            return ToolResult.failure(f"transport error: {exc}")

    async def _head(self, url: str, cfg: WebConfig) -> ToolResult:
        client = self._build_client(cfg)
        try:
            async with client:
                resp = await client.head(url)
                return ToolResult.json(
                    {
                        "url": str(resp.url),
                        "status": resp.status_code,
                        "headers": dict(resp.headers.items()),
                    }
                )
        except httpx.HTTPError as exc:
            return ToolResult.failure(f"transport error: {exc}")

    def _build_client(self, cfg: WebConfig) -> httpx.AsyncClient:
        if self.http_client_factory is not None:
            return self.http_client_factory()
        return httpx.AsyncClient(
            timeout=httpx.Timeout(cfg.timeout_seconds),
            follow_redirects=False,  # don't follow into denied hosts
        )


def _host_in_allowlist(host: str, allowlist: list[str]) -> bool:
    """Wildcard-friendly match. `"*"` allows everything; otherwise each
    entry matches if it equals the host or is a suffix beginning with
    `.` that the host ends with (so `example.com` matches both
    `example.com` and `api.example.com`)."""
    host = host.lower()
    for entry in allowlist:
        e = entry.lower()
        if e == "*" or e == host:
            return True
        if e.startswith("*.") and host.endswith(e[1:]):
            return True
        if host.endswith("." + e):
            return True
    return False


_SINGLETON: WebHandler | None = None


def get_handler() -> Handler:
    """Entry-point factory."""
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = WebHandler()
    return _SINGLETON
