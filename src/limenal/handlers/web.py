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
from urllib.parse import urlparse, urlunparse

import anyio
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
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT shared space (RFC 6598)
    ipaddress.ip_network("0.0.0.0/8"),       # "This" network (RFC 1122 §3.2.1.3)
    ipaddress.ip_network("224.0.0.0/4"),     # multicast
    ipaddress.ip_network("240.0.0.0/4"),     # reserved
    ipaddress.ip_network("255.255.255.255/32"),  # limited broadcast
    ipaddress.ip_network("::/128"),          # unspecified
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),        # ULA
    ipaddress.ip_network("fe80::/10"),       # link-local
    ipaddress.ip_network("::ffff:0:0/96"),   # v4-mapped IPv6 (belt-and-suspenders)
]


def _embedded_v4s(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> list[ipaddress.IPv4Address]:
    """Extract any IPv4 address embedded in an IPv6 address.

    An IPv6 address can wrap a v4 target that a gateway translates back to
    IPv4 at connect time — so the embedded v4 must also be checked against
    the IPv4 deny ranges, or a metadata/loopback IP slips past wearing an
    IPv6 disguise. Three transition mechanisms embed a v4:

      - v4-mapped (::ffff:a.b.c.d) — already blanket-denied by the
        ::ffff:0:0/96 range in PRIVATE_NETWORKS; unwrapped here belt-and-
        suspenders so the check stays correct if someone ever narrows that
        range.
      - 6to4 (2002::/16) — bytes 2-5 carry the v4 (ip.sixtofour).
      - NAT64 (64:ff9b::/96 well-known prefix) — the low 32 bits carry the
        v4; a DNS64 resolver synthesizes e.g. 64:ff9b::a9fe:a9fe for
        169.254.169.254, which is neither v4-mapped nor 6to4.
    """
    out: list[ipaddress.IPv4Address] = []
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            out.append(ip.ipv4_mapped)
        if ip.sixtofour is not None:
            out.append(ip.sixtofour)
        if ip in ipaddress.ip_network("64:ff9b::/96"):
            out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out

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

    async def startup(self) -> None:
        self._shared_client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.default_config.timeout_seconds),
            follow_redirects=False,
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
            # Also check any IPv4 embedded in an IPv6 address (v4-mapped,
            # 6to4, NAT64) against the IPv4 deny ranges — a gateway
            # translates those back to IPv4 at connect time, so the wrapped
            # metadata/loopback IP would otherwise evade every v4 rule.
            ips_to_check: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [
                ip,
                *_embedded_v4s(ip),
            ]
            for check_ip in ips_to_check:
                for net in cfg.denied_networks:
                    if check_ip in net:
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
        max_bytes = min(
            int(payload.get("max_bytes") or cfg.max_response_bytes),
            cfg.max_response_bytes,
        )
        request_url, extra_headers = _pin_to_ip(url, validated_ip)
        client, owned = self._get_client(cfg)
        try:
            async with client.stream("GET", request_url, headers=extra_headers) as resp:
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
        request_url, extra_headers = _pin_to_ip(url, validated_ip)
        client, owned = self._get_client(cfg)
        try:
            resp = await client.head(request_url, headers=extra_headers)
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
                headers_raw = {"x-limenal-warning": "response headers exceeded size cap"}
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

    def _get_client(self, cfg: WebConfig) -> tuple[httpx.AsyncClient, bool]:
        """Return (client, owned). owned=True means the caller must close it."""
        if self.http_client_factory is not None:
            return self.http_client_factory(), True
        if self._shared_client is not None:
            return self._shared_client, False
        # No pooled client yet (lifespan not called) — create a per-request one.
        return httpx.AsyncClient(
            timeout=httpx.Timeout(cfg.timeout_seconds),
            follow_redirects=False,
        ), True


def _pin_to_ip(url: str, ip: str | None) -> tuple[str, dict[str, str]]:
    """Return (request_url, extra_headers) with the hostname replaced by `ip`.

    For HTTP schemes we swap the hostname for the pre-validated IP and return
    a `Host` header preserving the original hostname. This closes the TOCTOU
    gap between our DNS validation check and httpx's internal re-resolution:
    httpx connects to exactly the IP we verified, not whatever DNS returns at
    connect time.

    For HTTPS we leave the URL unchanged — TLS certificate validation binds
    the connection to the original hostname, so a rebinding attack would fail
    cert verification. If no ip is provided (dns_resolver stub in tests that
    returns no IPs), we also leave the URL unchanged.
    """
    if ip is None:
        return url, {}
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        return url, {}
    if parsed.scheme != "http":
        return url, {}
    host = parsed.hostname or ""
    port = parsed.port
    if port:
        new_netloc = f"{ip}:{port}"
    else:
        new_netloc = ip
    pinned = urlunparse(parsed._replace(netloc=new_netloc))
    return pinned, {"Host": host}


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
