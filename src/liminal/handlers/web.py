"""web — allowlisted HTTP fetch with SSRF defense.

URL policy: a per-caller hostname allowlist in
`ctx.extra["web.allowed_hosts"]` (from the token's tool_extras in
single-cabal mode, or the trust registry's [tool_extras] in sovereign mode);
without one the handler's default allowlist applies. Private, loopback,
link-local and other internal ranges (PRIVATE_NETWORKS) are refused on every
resolved IP whatever the allowlist says, as SSRF protection against pivoting
through the agent to internal services or cloud metadata.

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

import anyio
import httpx
import structlog

from liminal.handlers._netpolicy import PRIVATE_NETWORKS, denied_network
from liminal.protocol import Context, Handler, ToolResult, ToolSpec

log = structlog.get_logger(__name__)


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
    "required_scope": "web:fetch",
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

    Call `await startup()` / `await shutdown()` from the app lifespan to
    enable a shared pooled AsyncClient across requests.
    """

    default_config: WebConfig = field(default_factory=WebConfig)
    http_client_factory: Any = None  # () -> httpx.AsyncClient
    dns_resolver: Any = None  # (host) -> list[str] (returns IPs)
    _shared_client: httpx.AsyncClient | None = field(default=None, init=False)

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
                            "description": "Override the default response-size cap; clamped to 1..the handler's cap.",
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

    async def startup(self) -> None:
        self._shared_client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.default_config.timeout_seconds),
            follow_redirects=False,
            trust_env=False,  # an env proxy would send the pinned IP as SNI (issue #204)
        )

    async def shutdown(self) -> None:
        if self._shared_client is not None:
            await self._shared_client.aclose()
            self._shared_client = None

    def capability_card(self) -> dict[str, Any]:
        return CARD

    async def dispatch(
        self, name: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        url = payload.get("url")
        if not isinstance(url, str) or not url:
            return ToolResult.failure("'url' must be a non-empty string")

        cfg = self._resolve_config(ctx)
        check_err, validated_ip = await self._check_url(url, cfg)
        if check_err is not None:
            return ToolResult.failure(check_err)

        if name == "fetch":
            return await self._fetch(url, payload, cfg, validated_ip)
        if name == "head":
            return await self._head(url, cfg, validated_ip)
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

    async def _check_url(
        self, url: str, cfg: WebConfig
    ) -> tuple[str | None, str | None]:
        """Validate the URL and return (error, validated_ip).

        Returns (error_msg, None) on refusal or (None, first_valid_ip) on
        success. The validated IP should be pinned at connect time to prevent
        DNS-rebinding: the caller resolves once here and httpx must not
        re-resolve at connect time.
        """
        try:
            parsed = urlparse(url)
        except Exception:  # noqa: BLE001
            return f"unparseable URL: {url!r}", None
        if parsed.scheme not in {"http", "https"}:
            return f"scheme {parsed.scheme!r} not allowed; only http/https", None
        host = parsed.hostname
        if not host:
            return "URL missing hostname", None

        if not _host_in_allowlist(host, cfg.allowed_hosts):
            return f"host {host!r} not in allowlist {cfg.allowed_hosts}", None

        # JWT can narrow, never widen: also enforce the server-side ceiling.
        if cfg is not self.default_config and not _host_in_allowlist(
            host, self.default_config.allowed_hosts
        ):
            return f"host {host!r} not permitted by server configuration", None

        resolved_ips = await self._resolve(host)
        if not resolved_ips:
            return f"could not resolve host {host!r}", None
        first_valid: str | None = None
        for ip_str in resolved_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                return f"invalid IP {ip_str!r} from DNS", None
            # denied_network also checks any IPv4 embedded in an IPv6 address
            # (v4-mapped, 6to4, NAT64, IPv4-compatible): a gateway translates
            # those back to IPv4 at connect time (handlers/_netpolicy.py).
            net = denied_network(ip, cfg.denied_networks)
            if net is not None:
                return (
                    f"host {host!r} resolves to {ip_str} in denied "
                    f"network {net} (SSRF protection)"
                ), None
            if first_valid is None:
                first_valid = ip_str
        return None, first_valid

    async def _resolve(self, host: str) -> list[str]:
        if self.dns_resolver is not None:
            try:
                result = self.dns_resolver(host)
                # Allow both sync and async resolvers (tests often inject sync stubs)
                if hasattr(result, "__await__"):
                    result = await result
                return result
            except Exception as exc:  # noqa: BLE001
                log.warning("web.dns_resolver_failed", host=host, error=str(exc))
                return []
        try:
            infos = await anyio.to_thread.run_sync(
                lambda: socket.getaddrinfo(host, None)
            )
        except socket.gaierror:
            return []
        return [info[4][0] for info in infos]

    # ---- fetch + head -------------------------------------------------

    async def _fetch(
        self, url: str, payload: dict[str, Any], cfg: WebConfig, validated_ip: str | None
    ) -> ToolResult:
        raw_max = payload.get("max_bytes")
        if raw_max is None:
            max_bytes = cfg.max_response_bytes
        elif isinstance(raw_max, bool) or not isinstance(raw_max, int):
            # int() used to raise here, and the agent saw only
            # "web.fetch raised ValueError" (#193).
            return ToolResult.failure(
                f"'max_bytes' must be an integer, got {type(raw_max).__name__}"
            )
        else:
            # Below 1 used to slice the tail off the body (body[:-5]).
            max_bytes = max(1, min(raw_max, cfg.max_response_bytes))
        request_url, extra_headers, extensions = _pin_request(url, validated_ip)
        client, owned = self._get_client(cfg, isolated=bool(extensions))
        try:
            async with client.stream(
                "GET", request_url, headers=extra_headers, extensions=extensions
            ) as resp:
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
                        "url": url,
                        "status": resp.status_code,
                        "content_type": content_type,
                        "bytes": len(body),
                        "truncated": truncated,
                        "text": text,
                    }
                )
        except httpx.HTTPError as exc:
            return ToolResult.failure(f"transport error: {exc}")
        finally:
            if owned:
                await client.aclose()

    async def _head(self, url: str, cfg: WebConfig, validated_ip: str | None) -> ToolResult:
        request_url, extra_headers, extensions = _pin_request(url, validated_ip)
        client, owned = self._get_client(cfg, isolated=bool(extensions))
        try:
            resp = await client.head(request_url, headers=extra_headers, extensions=extensions)
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
            # Cap headers to prevent leaking large internal header sets.
            max_header_bytes = 16_384
            headers_raw = dict(resp.headers.items())
            total = sum(len(k) + len(v) for k, v in headers_raw.items())
            if total > max_header_bytes:
                headers_raw = {"x-liminal-warning": "response headers exceeded size cap"}
            return ToolResult.json(
                {
                    "url": url,
                    "status": resp.status_code,
                    "headers": headers_raw,
                }
            )
        except httpx.HTTPError as exc:
            return ToolResult.failure(f"transport error: {exc}")
        finally:
            if owned:
                await client.aclose()

    def _get_client(
        self, cfg: WebConfig, isolated: bool = False
    ) -> tuple[httpx.AsyncClient, bool]:
        """Return (client, owned). owned=True means the caller must close it.

        isolated=True skips the shared pool (a pinned https request, see
        _pin_request)."""
        if self.http_client_factory is not None:
            return self.http_client_factory(), True
        if self._shared_client is not None and not isolated:
            return self._shared_client, False
        # No pooled client yet (lifespan not called) — create a per-request one.
        return httpx.AsyncClient(
            timeout=httpx.Timeout(cfg.timeout_seconds),
            follow_redirects=False,
            trust_env=False,  # an env proxy would send the pinned IP as SNI (issue #204)
        ), True


def _pin_request(
    url: str, ip: str | None
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Return (request_url, extra_headers, extensions) that connect to `ip`.

    The hostname in the URL becomes the pre-validated IP (bracketed for IPv6,
    liminal#195), so httpx connects to exactly the address we checked rather
    than re-resolving at connect time. `Host` keeps the original name (and a
    non-default port). For https the `sni_hostname` extension makes httpcore
    send the original name as SNI and verify the certificate against it, so
    https is pinned too (liminal#196): a rebinding name can no longer steer the
    TCP connect to an internal address.

    A pinned https request must not share a pooled connection: the pool is
    keyed by the IP, so a later request for another name at the same IP would
    reuse a TLS session verified for the first name. Callers give a request
    with extensions its own client.

    With no ip (a test resolver that returns none) the URL is unchanged.
    """
    if ip is None:
        return url, {}, {}
    # Parse with httpx, not urlparse, so the pinned URL keeps what httpx needs
    # (PR 203 review): userinfo (httpx turns it into Basic auth, which webhook
    # URLs carry), the IDNA form of a non-ASCII host (urlparse's Unicode name
    # can't go in a header), and httpx's own default-port rule for Host.
    try:
        parsed = httpx.URL(url)
    except httpx.InvalidURL:
        return url, {}, {}
    if parsed.scheme not in ("http", "https"):
        return url, {}, {}
    pinned = parsed.copy_with(host=ip)  # brackets an IPv6 address itself
    # netloc: IDNA host, port only when non-default, no userinfo.
    host_header = parsed.netloc.decode("ascii")
    extensions: dict[str, Any] = (
        {"sni_hostname": parsed.raw_host.decode("ascii")} if parsed.scheme == "https" else {}
    )
    return str(pinned), {"Host": host_header}, extensions


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
