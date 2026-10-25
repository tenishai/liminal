"""notify — transport-agnostic notifications.

The persona calls `notify.send(message, ...)`. The operator picks the
transport (webhook → Slack/Discord/IFTTT/ntfy/anything-that-accepts-POST).
The persona's prompt and tool surface stay the same when the operator
swaps Slack for Discord.

Architecture:
- One handler exposes one tool surface (notify.send + notify.list_transports).
- Multiple `Transport` implementations registered at construction. The
  active transport per dispatch is picked from `ctx.extra["notify.transport"]`,
  falling back to the handler's `default_transport`.
- Each transport reads its own config from `ctx.credentials` (URLs and
  tokens go through the cabal_tool_extras + secrets paths the rest of
  the platform already uses).

Phase LL v1 ships ONE transport: `webhook`. POSTs JSON `{title, message,
level, persona, agent_name}` to a URL the operator configures per
persona. Sufficient for Slack incoming webhooks, Discord webhooks, ntfy,
IFTTT, custom internal endpoints, etc.

Phase 2+ transports plug in here: each is a subclass of `Transport`
with its own `send` method and credential_keys. Operators register the
ones they want; capability_card declares the union.

Defenses on the webhook transport (inherited from web's SSRF lessons):
- URL must be http/https.
- URL hostname must resolve to a NON-private IP (loopback, RFC1918,
  link-local, metadata service all denied).
- Body capped at WEBHOOK_MAX_BODY_BYTES.
- Per-persona allowlist via `ctx.extra["notify.allowed_hosts"]`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any
from urllib.parse import urlparse

import anyio
import httpx
import structlog

from liminal.handlers.web import PRIVATE_NETWORKS, _host_in_allowlist, _pin_request
from liminal.protocol import Context, Handler, ToolResult, ToolSpec

log = structlog.get_logger(__name__)


LEVELS = ("info", "warning", "error")
WEBHOOK_MAX_BODY_BYTES = 16_000


CARD = {
    "handler": "notify",
    "required_scope": "notify:send",
    "description": "Transport-agnostic notifications (webhook in v1; Slack/Discord/email plug in later).",
    "tools": [
        {"name": "send", "description": "Send a notification via the configured transport."},
        {"name": "list_transports", "description": "List configured transports."},
    ],
    "activation": "always",
    "credential_keys": [],
    "labels": {"tier": "builtin"},
}


# ---- Transport Protocol --------------------------------------------------


class Transport(ABC):
    """One backend (webhook, slack, discord, email, ...).

    A transport is responsible for translating the unified `send` call
    into a backend-specific request. It reads its own config from
    `ctx.credentials` and `ctx.extra` — liminal hands it the dict; the
    transport picks what it needs.
    """

    name: str

    @property
    @abstractmethod
    def credential_keys(self) -> list[str]:
        """Document which credentials the transport reads."""

    @abstractmethod
    async def send(
        self,
        *,
        message: str,
        level: str,
        title: str | None,
        ctx: Context,
    ) -> dict[str, Any]:
        """Send a notification. Returns metadata; raises on hard failure."""


# ---- Webhook transport ---------------------------------------------------


@dataclass
class WebhookTransport(Transport):
    """POST a JSON body to a configured URL.

    URL source (in order): `ctx.credentials["NOTIFY_WEBHOOK_URL"]` ←
    operator can put it in the secrets table; or `ctx.extra["notify.webhook_url"]`
    ← convenience for tests / non-credential URL like a public ntfy
    endpoint. The credentials path is the canonical "I'm storing a
    Slack incoming-webhook URL" route.

    Operator constrains targets via `ctx.extra["notify.allowed_hosts"]`
    — same wildcard / glob / suffix matcher as the web handler.

    `server_allowed_hosts` is the operator-configured ceiling. JWT-supplied
    `notify.allowed_hosts` in ctx.extra can only narrow within this set.
    Default `["*"]` means no server-side restriction.
    """

    name: str = "webhook"
    http_client_factory: Any = None
    dns_resolver: Any = None
    denied_networks: list[Any] = field(default_factory=lambda: list(PRIVATE_NETWORKS))
    timeout_seconds: float = 10.0
    server_allowed_hosts: list[str] = field(default_factory=lambda: ["*"])
    #: The operator's webhook URL (LIMINAL_NOTIFY_WEBHOOK_URL, liminal#197), used
    #: when the caller's credentials and tool extras name none: under auth-off
    #: both are empty, so without this the default transport could never send.
    default_url: str | None = None
    _shared_client: httpx.AsyncClient | None = field(default=None, init=False)

    @property
    def credential_keys(self) -> list[str]:
        return ["NOTIFY_WEBHOOK_URL"]

    async def send(
        self,
        *,
        message: str,
        level: str,
        title: str | None,
        ctx: Context,
    ) -> dict[str, Any]:
        url = (
            ctx.credentials.get("NOTIFY_WEBHOOK_URL")
            or ctx.extra.get("notify.webhook_url")
            or self.default_url
        )
        if not url:
            raise NotifyError(
                "webhook URL not configured "
                "(set NOTIFY_WEBHOOK_URL via `cbl secret set`, pass "
                "notify.webhook_url in tool_extras, or set "
                "LIMINAL_NOTIFY_WEBHOOK_URL for the server)"
            )
        err, validated_ip = await _check_url(
            url,
            ctx,
            denied_networks=self.denied_networks,
            resolver=self._resolve,
            server_allowed_hosts=self.server_allowed_hosts,
        )
        if err is not None:
            raise NotifyError(err)

        payload = {
            "title": title,
            "message": message,
            "level": level,
            "persona": ctx.identity,
            "agent_name": ctx.agent_name,
        }
        body = json.dumps(payload).encode("utf-8")
        if len(body) > WEBHOOK_MAX_BODY_BYTES:
            raise NotifyError(
                f"webhook body is {len(body)} bytes; "
                f"exceeds {WEBHOOK_MAX_BODY_BYTES}"
            )

        request_url, extra_headers, extensions = _pin_request(url, validated_ip)
        client, owned = self._get_client(isolated=bool(extensions))
        try:
            resp = await client.post(
                request_url,
                content=body,
                headers={"content-type": "application/json", **extra_headers},
                extensions=extensions,
            )
        except httpx.HTTPError as exc:
            # The webhook URL is a credential (its path/query/userinfo often
            # carry the secret), and httpx exception text is free-form, so the
            # caller gets the exception class and a fixed reason, never str(exc)
            # (liminal#149).
            raise NotifyError(
                f"webhook POST failed: {type(exc).__name__} ({_post_failure_reason(exc)})"
            ) from exc
        finally:
            if owned:
                await client.aclose()

        # No URL-derived field beyond the host: the full URL is the credential
        # (liminal#149).
        return {
            "transport": "webhook",
            "host": urlparse(url).hostname,
            "status": resp.status_code,
            "ok": 200 <= resp.status_code < 300,
        }

    async def startup(self) -> None:
        self._shared_client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
        )

    async def shutdown(self) -> None:
        if self._shared_client is not None:
            await self._shared_client.aclose()
            self._shared_client = None

    def _get_client(self, isolated: bool = False) -> tuple[httpx.AsyncClient, bool]:
        """Return (client, owned). owned=True means the caller must close it.

        isolated=True skips the shared pool (a pinned https request, see
        web._pin_request)."""
        if self.http_client_factory is not None:
            return self.http_client_factory(), True
        if self._shared_client is not None and not isolated:
            return self._shared_client, False
        return httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
        ), True

    async def _resolve(self, host: str) -> list[str]:
        if self.dns_resolver is not None:
            try:
                result = self.dns_resolver(host)
                if hasattr(result, "__await__"):
                    result = await result
                return result
            except Exception as exc:  # noqa: BLE001
                log.warning("notify.dns_resolver_failed", host=host, error=str(exc))
                return []
        try:
            infos = await anyio.to_thread.run_sync(
                lambda: socket.getaddrinfo(host, None)
            )
        except socket.gaierror:
            return []
        return [info[4][0] for info in infos]


# ---- Stdout transport ----------------------------------------------------


@dataclass
class StdoutTransport(Transport):
    """Print to a file-like stream — stderr by default.

    Useful for:
      - dev (operator runs `liminal serve` and watches notifications fly
        by alongside the daemon log)
      - audit-style overlay (operator wires it as a secondary transport
        so every notification is also logged locally)
      - tests (capture the stream and assert)

    No credentials, no network, no SSRF surface. Cannot fail in any way
    the agent needs to handle structurally — `notify.send` always
    succeeds against this transport.
    """

    name: str = "stdout"
    # Injectable for tests — defaults to None so we resolve to sys.stderr
    # at send-time (don't capture the module-import-time sys.stderr).
    stream: Any = None
    timestamp: bool = True

    @property
    def credential_keys(self) -> list[str]:
        return []

    async def send(
        self,
        *,
        message: str,
        level: str,
        title: str | None,
        ctx: Context,
    ) -> dict[str, Any]:
        import sys
        from datetime import datetime

        target = self.stream if self.stream is not None else sys.stderr

        prefix_parts: list[str] = []
        if self.timestamp:
            prefix_parts.append(datetime.now(UTC).isoformat(timespec="seconds"))
        prefix_parts.append(f"[{level.upper()}]")
        prefix_parts.append(f"[{ctx.identity}:{ctx.agent_name}]")
        if title:
            prefix_parts.append(f"{title}:")

        # One log line per call (liminal#197): caller text with a newline could
        # otherwise write lines that look like liminal's own ("[warning] ...").
        line = _one_line(" ".join(prefix_parts) + " " + message)
        print(line, file=target, flush=True)
        return {"transport": "stdout", "ok": True, "bytes": len(line)}


# ---- The handler ---------------------------------------------------------


class NotifyError(RuntimeError):
    pass


@dataclass
class NotifyHandler:
    """Routes `notify.send` to the active transport.

    `transports` is a dict[name → Transport]. `default_transport` is
    used when ctx.extra doesn't pick one. Adding a Slack/Discord/email
    transport later: subclass Transport, instantiate, add to the dict.
    """

    transports: dict[str, Transport] = field(default_factory=dict)
    default_transport: str = "webhook"

    def __post_init__(self) -> None:
        # Ship webhook + stdout by default so:
        #   - The operator can use notify.send out of the box against any
        #     URL they configure (webhook).
        #   - Dev / audit / tests can use stdout without configuring
        #     anything; the operator picks per-call with transport="stdout".
        if not self.transports:
            self.transports = {
                "webhook": WebhookTransport(),
                "stdout": StdoutTransport(),
            }

    def tools(self) -> list[ToolSpec]:
        return [
            ToolSpec(
                name="send",
                description="Send a notification via the configured transport.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "message": {"type": "string"},
                        "level": {"type": "string", "enum": list(LEVELS), "default": "info"},
                        "title": {"type": "string"},
                        "transport": {
                            "type": "string",
                            "description": "Which transport to use; falls back to ctx.extra or default.",
                        },
                    },
                    "required": ["message"],
                },
            ),
            ToolSpec(
                name="list_transports",
                description="List configured transports + their declared credential keys.",
                input_schema={"type": "object", "properties": {}},
            ),
        ]

    def capability_card(self) -> dict[str, Any]:
        # Union of credential keys across registered transports — handlers
        # downstream may read this to know what to provision.
        all_keys: set[str] = set()
        for t in self.transports.values():
            all_keys.update(t.credential_keys)
        card = dict(CARD)
        card["credential_keys"] = sorted(all_keys)
        return card

    async def dispatch(
        self, name: str, payload: dict[str, Any], ctx: Context
    ) -> ToolResult:
        if name == "send":
            return await self._send(payload, ctx)
        if name == "list_transports":
            return self._list_transports()
        return ToolResult.failure(f"unknown tool {name!r}")

    async def _send(self, payload: dict[str, Any], ctx: Context) -> ToolResult:
        message = payload.get("message")
        if not isinstance(message, str) or not message.strip():
            return ToolResult.failure("'message' must be a non-empty string")

        level = payload.get("level", "info")
        if level not in LEVELS:
            return ToolResult.failure(
                f"'level' must be one of {list(LEVELS)}; got {level!r}"
            )
        title = payload.get("title")
        if title is not None and not isinstance(title, str):
            return ToolResult.failure("'title' must be a string")

        # Pick transport: payload > ctx.extra > default
        transport_name = (
            payload.get("transport")
            or ctx.extra.get("notify.transport")
            or self.default_transport
        )
        transport = self.transports.get(transport_name)
        if transport is None:
            return ToolResult.failure(
                f"transport {transport_name!r} not configured "
                f"(available: {sorted(self.transports.keys())})"
            )

        try:
            result = await transport.send(
                message=message, level=level, title=title, ctx=ctx
            )
        except NotifyError as exc:
            return ToolResult.failure(str(exc))

        return ToolResult.json({"transport": transport_name, **result})

    def _list_transports(self) -> ToolResult:
        return ToolResult.json(
            {
                "transports": [
                    {"name": t.name, "credential_keys": list(t.credential_keys)}
                    for t in self.transports.values()
                ],
                "default": self.default_transport,
            }
        )


def _post_failure_reason(exc: httpx.HTTPError) -> str:
    """A fixed, URL-free reason for a failed webhook POST."""
    if isinstance(exc, httpx.TimeoutException):
        return "timed out"
    if isinstance(exc, httpx.ConnectError):
        return "connection failed"
    return "request failed"


# ---- URL safety (mirrors web handler's SSRF defense) ---------------------


async def _check_url(
    url: str,
    ctx: Context,
    *,
    denied_networks: list[Any],
    resolver: Any,
    server_allowed_hosts: list[str] | None = None,
) -> tuple[str | None, str | None]:
    """Validate and return (error, validated_ip). See web._check_url for rationale."""
    try:
        parsed = urlparse(url)
    except Exception:  # noqa: BLE001
        # No URL in the message: it may be the NOTIFY_WEBHOOK_URL credential.
        return "unparseable webhook URL", None
    if parsed.scheme not in {"http", "https"}:
        return f"scheme {parsed.scheme!r} not allowed; only http/https", None
    host = parsed.hostname
    if not host:
        return "URL missing hostname", None

    allowed = ctx.extra.get("notify.allowed_hosts") or ["*"]
    if not _host_in_allowlist(host, list(allowed)):
        return f"host {host!r} not in allowlist {list(allowed)}", None

    # JWT can narrow, never widen: enforce server-side ceiling.
    if server_allowed_hosts and not _host_in_allowlist(host, server_allowed_hosts):
        return f"host {host!r} not permitted by server configuration", None

    resolved_ips = await resolver(host)
    if not resolved_ips:
        return f"could not resolve host {host!r}", None
    first_valid: str | None = None
    for ip_str in resolved_ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return f"invalid IP {ip_str!r} from DNS", None
        for net in denied_networks:
            if ip in net:
                return (
                    f"host {host!r} resolves to {ip_str} in denied "
                    f"network {net} (SSRF protection)"
                ), None
        if first_valid is None:
            first_valid = ip_str
    return None, first_valid


_SINGLETON: NotifyHandler | None = None


def _one_line(text: str) -> str:
    return " ".join(text.splitlines())


def get_handler() -> Handler:
    """Entry-point factory, configured from the environment (liminal#197).

    Under auth-off the caller's credentials and tool extras are empty, so the
    server's own config is the only source of a webhook URL:

      LIMINAL_NOTIFY_WEBHOOK_URL     the webhook every caller without one uses
      LIMINAL_NOTIFY_ALLOWED_HOSTS   comma-separated host ceiling (default: any)
      LIMINAL_NOTIFY_STDOUT=1        also offer the stdout transport

    stdout is opt-in because it writes caller-chosen text into the server's own
    log, and the caller picks the transport per call. Read the same way files
    and memory read LIMINAL_FILES_ALLOWED_PATHS and LIMINAL_MEMORY_DB."""
    global _SINGLETON
    if _SINGLETON is None:
        hosts = [
            h.strip()
            for h in os.environ.get("LIMINAL_NOTIFY_ALLOWED_HOSTS", "").split(",")
            if h.strip()
        ]
        webhook = WebhookTransport(
            default_url=os.environ.get("LIMINAL_NOTIFY_WEBHOOK_URL") or None,
            server_allowed_hosts=hosts or ["*"],
        )
        transports: dict[str, Transport] = {"webhook": webhook}
        if os.environ.get("LIMINAL_NOTIFY_STDOUT") == "1":
            transports["stdout"] = StdoutTransport()
        _SINGLETON = NotifyHandler(transports=transports)
    return _SINGLETON
